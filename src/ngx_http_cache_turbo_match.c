/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Cookie / query-argument / URI matching group (MAINT-SPLIT). Split out of
 * ngx_http_cache_turbo_module.c: the bounded Cookie substring machinery, the
 * percent-decoding query-string comparator and argument parser, the
 * segment-boundary URI prefix matcher, the auto-classify gate that consumes
 * them, and the three config-driven walkers built on the same matchers
 * (bypass_uri, bypass_stale_uri, key-cookie lookup).
 *
 * FUZZ-EXTRACT: this file carries its OWN "auto-classify BEGIN/END" marker
 * pair, exactly as ngx_http_cache_turbo_presets.c does. Everything that used
 * to sit between module.c's markers now sits between THIS file's, moved
 * verbatim, so ci/fuzz/extract_auto_classify.sh slices presets.c then this
 * file and produces a byte-identical generated_auto_classify.inc. The fuzz
 * target keeps exercising the shipped gate with no copy drift. See that
 * script for the concatenation order.
 *
 * The includes stay OUTSIDE the markers so the generated .inc never gains a
 * project-header dependency — it is compiled against ci/fuzz/ngx_shim_auto.h
 * alone. So do the three config-driven walkers at the end of the file: they
 * read ngx_http_cache_turbo_loc_conf_t, which the fuzz shim does not model,
 * and they sat outside module.c's END marker before the split too.
 *
 * Export surface: six functions lose `static` because module.c still calls
 * them across the TU boundary (auto_skip, key_cookie, cookie_lookup,
 * bypass_uri_match, bypass_stale_uri_match, and hexval — which the hex-decode
 * helpers in module.c share, the reason the comment above hexval gives for it
 * living inside the FUZZ region). They are declared in
 * ngx_http_cache_turbo_internal.h. Everything else stays file-local static.
 * No function had `ngx_inline`, so nothing needed that qualifier dropped.
 */

#include "ngx_http_cache_turbo_module.h"
#include "ngx_http_cache_turbo_internal.h"

/* R5-1 (perf-microtier-hitpath): default-hide every symbol this TU defines
 * so a module-internal call becomes a direct call instead of a PLT-indirect
 * one (see ngx_http_cache_turbo_module.h for why this is a per-file pragma
 * rather than a global -fvisibility=hidden CFLAGS addition, and why a
 * header-only pragma does not work). Anything in this file that nginx's
 * dynamic-module loader must resolve by name gets an explicit
 * __attribute__((visibility("default"))) at its definition, overriding this
 * pragma (GCC: an explicit attribute always wins over the pragma). */
#pragma GCC visibility push(hidden)


/* >>> FUZZ-EXTRACT auto-classify BEGIN (ci/fuzz/extract_auto_classify.sh) <<< */
/*
 * S231-PERF-AUTOCLASSIFY: bounded Cookie substring classification. nginx's
 * default large_client_header_buffers size is 8 KiB, so a single accepted
 * Cookie field is already bounded there on a default server (the runtime
 * large-Cookie fixture deliberately stays just below it). Multiple Cookie
 * fields can otherwise multiply that budget. Cap their AGGREGATE value bytes
 * at the same 8 KiB: a request over the cap is classified private/bypass, so
 * raising nginx's header limit can cost cache hits but can never make private
 * content cacheable. Splitting a Cookie across fields cannot multiply work.
 *
 * The set is built ONCE per request (ngx_http_cache_turbo_auto_skip(), before
 * the preset loop) by a single linear pass over every Cookie header value,
 * unioned across all of them. Needle first bytes are compile-time C string
 * literals, so (*pp)[0] needs no separate table.
 *
 * PROOF this cannot fail open: if cookie_contains(hay, needle) would return 1,
 * then needle[0] occurs in hay. The set contains every byte
 * occurring in ANY Cookie header value, so needle[0]'s bit is set, so the
 * prefilter does NOT skip that needle. The observable result of cookie_has()
 * is therefore byte-identical to the old implementation for every in-budget
 * input; the filter can only skip scans that were guaranteed to miss. Unioning
 * across multiple Cookie headers is a SUPERSET of any single header's bytes,
 * which only makes the filter weaker (fewer scans skipped), never wrong.
 *
 * cookie_has() computes each literal needle length ONCE, outside the Cookie-
 * field loop, then passes it to cookie_contains(). This avoids ngx_strnstr()'s
 * repeated NUL-length discovery without changing the registry's simple
 * NULL-terminated literal arrays. A zero-length registry needle is ambiguous
 * and therefore fails closed to bypass instead of entering the prefilter.
 */
#define NGX_HTTP_CACHE_TURBO_COOKIE_BYTES_MAX  8192

typedef struct {
    u_char  seen[256];
} ngx_http_cache_turbo_byteset_t;

#if defined(NGX_HTTP_CACHE_TURBO_AUTO_FIXTURES)
/* Deterministic unit-fixture oracle. Counts Cookie value bytes inspected by
 * byteset_build(), literal bytes read by the once-per-needle length pass, and
 * haystack/needle byte comparisons in cookie_contains(). It is absent from
 * production and fuzz builds; the fixture uses it to prove an operation bound
 * without a wall-clock timing band. */
static size_t  ngx_http_cache_turbo_cookie_work = 0;
#define ngx_http_cache_turbo_cookie_work_add(n)                              \
    (ngx_http_cache_turbo_cookie_work += (n))
#else
#define ngx_http_cache_turbo_cookie_work_add(n)  ((void) 0)
#endif

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
/* Test-only observable: counts bounded substring scans actually made by
 * cookie_has() across the whole request, so a runtime test can assert the
 * prefilter is cutting scans on a large Cookie header that matches nothing,
 * without resorting to a wall-clock timing band. Process-global, matching the
 * L2 backoff skip counters' convention -- reset is not needed because tests
 * read a DELTA across two requests, never an absolute value. */
ngx_atomic_uint_t  ngx_http_cache_turbo_test_cookie_scans = 0;
#endif

#if defined(NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO)
/* Union the bytes of every request Cookie header value into *bs. Must be
 * called once per request before any cookie_has() call in the same request.
 * Returns NGX_ERROR before inspecting an over-budget/null-backed value; the
 * caller maps every such sizing/shape ambiguity to private/bypass.
 *
 * Zeroes *bs itself with a plain loop rather than ngx_memzero(), so this
 * builder has no dependency on ngx_string.h beyond what cookie_has() already
 * needs -- the fuzz harness's minimal shim (ngx_shim_auto.h) does not supply
 * ngx_memzero(). */
static ngx_int_t
ngx_http_cache_turbo_cookie_byteset_build(ngx_http_request_t *r,
    ngx_http_cache_turbo_byteset_t *bs)
{
    ngx_uint_t           b;
    size_t               total;
#if (nginx_version >= 1023000)
    ngx_table_elt_t     *ck;
    u_char              *p, *end;
#else
    ngx_table_elt_t    **ckp;
    ngx_uint_t           i;
    u_char              *p, *end;
#endif

    for (b = 0; b < 256; b++) {
        bs->seen[b] = 0;
    }
    total = 0;

#if (nginx_version >= 1023000)
    for (ck = r->headers_in.cookie; ck; ck = ck->next) {
        if (ck->value.len == 0) {
            continue;
        }
        if (ck->value.data == NULL
            || ck->value.len > NGX_HTTP_CACHE_TURBO_COOKIE_BYTES_MAX - total)
        {
            return NGX_ERROR;
        }
        total += ck->value.len;
        for (p = ck->value.data, end = p + ck->value.len; p < end; p++) {
            bs->seen[*p] = 1;
            ngx_http_cache_turbo_cookie_work_add(1);
        }
    }
#else
    ckp = r->headers_in.cookies.elts;
    for (i = 0; i < r->headers_in.cookies.nelts; i++) {
        if (ckp[i]->value.len == 0) {
            continue;
        }
        if (ckp[i]->value.data == NULL
            || ckp[i]->value.len
               > NGX_HTTP_CACHE_TURBO_COOKIE_BYTES_MAX - total)
        {
            return NGX_ERROR;
        }
        total += ckp[i]->value.len;
        for (p = ckp[i]->value.data, end = p + ckp[i]->value.len;
             p < end; p++)
        {
            bs->seen[*p] = 1;
            ngx_http_cache_turbo_cookie_work_add(1);
        }
    }
#endif

    return NGX_OK;
}


/* Length-bounded, case-sensitive substring search with ngx_strnstr()'s Cookie
 * semantics: an embedded NUL terminates the searchable value. `nlen` is
 * precomputed once by cookie_has(), not rediscovered at every candidate byte.
 * The fixture-only counter records every byte comparison exactly. */
static ngx_int_t
ngx_http_cache_turbo_cookie_contains(u_char *data, size_t len,
    const char *needle, size_t nlen)
{
    size_t  i, limit, off;

    if (nlen == 0 || len < nlen) {
        return 0;
    }

    limit = len - nlen;

    for (off = 0; off <= limit; off++) {
        ngx_http_cache_turbo_cookie_work_add(1);

        if (data[off] == '\0') {
            return 0;
        }
        if (data[off] != (u_char) needle[0]) {
            continue;
        }

        for (i = 1; i < nlen; i++) {
            ngx_http_cache_turbo_cookie_work_add(1);

            if (data[off + i] == '\0') {
                return 0;
            }
            if (data[off + i] != (u_char) needle[i]) {
                break;
            }
        }

        if (i == nlen) {
            return 1;
        }
    }

    return 0;
}


/* True if any request Cookie header contains one of the NULL-terminated name
 * substrings (the login/session cookies carry dynamic suffixes, so a substring
 * match on the distinctive prefix is the right test, not an exact-name lookup).
 * `bs` is the request's byte-presence set (see above); the bounded substring
 * scan is skipped whenever needle[0] cannot occur in any Cookie header, per the
 * proof above. Needle-outer ordering precomputes its length once while retaining
 * the union-of-all-Cookie-fields result. */
static ngx_int_t
ngx_http_cache_turbo_cookie_has(ngx_http_request_t *r,
    const char *const *subs, const ngx_http_cache_turbo_byteset_t *bs)
{
    const char *const  *pp;
    size_t              nlen;
#if (nginx_version >= 1023000)
    ngx_table_elt_t    *ck;
#else
    ngx_table_elt_t   **ckp;
    ngx_uint_t          i;
#endif

    for (pp = subs; *pp; pp++) {
        nlen = ngx_strlen(*pp);
        ngx_http_cache_turbo_cookie_work_add(nlen + 1);

        if (nlen == 0) {
            return 1;                   /* ambiguous registry row: fail closed */
        }
        if (!bs->seen[(u_char) (*pp)[0]]) {
            continue;
        }

#if (nginx_version >= 1023000)
        for (ck = r->headers_in.cookie; ck; ck = ck->next) {
            if (ck->value.len == 0) {
                continue;
            }
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
            ngx_atomic_fetch_add(&ngx_http_cache_turbo_test_cookie_scans, 1);
#endif
            if (ngx_http_cache_turbo_cookie_contains(ck->value.data,
                                                     ck->value.len,
                                                     *pp, nlen))
            {
                return 1;
            }
        }
#else
        ckp = r->headers_in.cookies.elts;
        for (i = 0; i < r->headers_in.cookies.nelts; i++) {
            if (ckp[i]->value.len == 0) {
                continue;
            }
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
            ngx_atomic_fetch_add(&ngx_http_cache_turbo_test_cookie_scans, 1);
#endif
            if (ngx_http_cache_turbo_cookie_contains(ckp[i]->value.data,
                                                     ckp[i]->value.len,
                                                     *pp, nlen))
            {
                return 1;
            }
        }
#endif
    }

    return 0;
}
#endif /* NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO */


#if !defined(NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO)
static ngx_int_t
ngx_http_cache_turbo_cookie_ac_scan_one(ngx_http_cache_turbo_cookie_ac_t *ac,
    u_char *data, size_t len)
{
    ngx_http_cache_turbo_cookie_ac_node_t  *n;
    ngx_uint_t                              state;
    u_char                                 *p, *end;

    if (ac->nodes == NULL || ac->nnodes == 0 || data == NULL || len == 0) {
        return 0;
    }

    n = ac->nodes;
    if (n[0].match) {
        return 1;
    }

    state = 0;
    end = data + len;

    for (p = data; p < end; p++) {
        if (*p == '\0') {
            return 0;
        }

        state = (ngx_uint_t) n[state].next[*p];
        ngx_http_cache_turbo_cookie_work_add(1);

        if (n[state].match) {
            return 1;
        }
    }

    return 0;
}
#endif /* !NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO */


#if !defined(NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO)
static ngx_int_t
ngx_http_cache_turbo_cookie_ac_match(ngx_http_request_t *r,
    ngx_http_cache_turbo_cookie_ac_t *ac)
{
#if (nginx_version >= 1023000)
    ngx_table_elt_t  *ck;
#else
    ngx_table_elt_t **ckp;
    ngx_uint_t        i;
#endif

    if (ac->nodes == NULL || ac->nnodes == 0) {
        return 0;
    }

#if (nginx_version >= 1023000)
    for (ck = r->headers_in.cookie; ck; ck = ck->next) {
        if (ck->value.len == 0) {
            continue;
        }
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
        ngx_atomic_fetch_add(&ngx_http_cache_turbo_test_cookie_scans, 1);
#endif
        if (ngx_http_cache_turbo_cookie_ac_scan_one(ac, ck->value.data,
                                                    ck->value.len))
        {
            return 1;
        }
    }
#else
    ckp = r->headers_in.cookies.elts;
    for (i = 0; i < r->headers_in.cookies.nelts; i++) {
        if (ckp[i]->value.len == 0) {
            continue;
        }
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
        ngx_atomic_fetch_add(&ngx_http_cache_turbo_test_cookie_scans, 1);
#endif
        if (ngx_http_cache_turbo_cookie_ac_scan_one(ac, ckp[i]->value.data,
                                                    ckp[i]->value.len))
        {
            return 1;
        }
    }
#endif

    return 0;
}
#endif /* !NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO */


/*
 * Cookie VALUE predicates (tier 2). The substring matcher above tests only that
 * a cookie NAME appears somewhere in the header. Some applications cannot be
 * classified that way at all: they issue the same cookie to guests and members
 * and encode the distinction in its VALUE. phpBB is the type case — every
 * non-bot visitor gets <prefix>_u, a guest's holds ANONYMOUS (the literal 1) and
 * a member's holds their user_id (never 1, ANONYMOUS is a reserved row). A
 * presence rule there matches all traffic and identifies nobody; a value rule
 * separates them exactly.
 *
 * TWO PROPERTIES OF THIS PARSER ARE LOAD-BEARING. Both were derived from the
 * upstream source, not assumed:
 *
 * 1. NAME-SUFFIX MATCHING, not exact names. phpBB's cookie is
 *    $config['cookie_name'] . '_u' (phpbb/session.php, set_cookie()), and
 *    cookie_name is an ACP setting — it defaults to "phpbb" (so the wire name is
 *    "phpbb_u") but installers randomise it and any admin running two boards on
 *    one domain changes it. A rule keyed on a literal name silently STOPS
 *    MATCHING on such a board, and a bypass rule that stops matching means the
 *    member's page is cached and served to strangers. Matching the name SUFFIX
 *    ("_u") is prefix-agnostic and therefore safe. It can over-match an
 *    unrelated cookie that happens to end in _u, which costs a needless bypass
 *    and never leaks — the correct direction to err.
 *
 * 2. UNPARSEABLE => BYPASS (fail closed to the cache, open to the origin). If
 *    the header is malformed, truncated, or the name matches with no '=' , we
 *    return "dynamic" rather than "cacheable". A false bypass costs one cache
 *    miss; a false hit costs somebody else's authenticated page. Every ambiguous
 *    path below returns 1.
 *
 * The value is compared against a literal (op EQ/NE) or merely required to be
 * non-empty (op NONEMPTY). Comparison is exact and length-checked: a cookie
 * "_u=10" must NOT satisfy "_u == 1".
 *
 * Cookie header grammar (RFC 6265 §4.2.1): cookie-pair *( ";" SP cookie-pair ).
 * We tolerate the sloppiness real clients emit — arbitrary OWS around ';' and
 * '=', missing SP, empty pairs — because a parser that only accepts well-formed
 * input would treat a malformed header as "no match" and, under a presence-only
 * reading, silently cache it. r->headers_in cookie values are NOT
 * NUL-terminated: every scan below is bounded by ck->value.len. (The fuzz
 * harness drives this function with arbitrary non-NUL-terminated bytes under
 * ASan for exactly this reason — ci/fuzz/ngx_shim_auto.h.)
 */


#if defined(NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO)
/* True if the cookie name [n, n+nlen) ends with the NUL-terminated suffix. */
static ngx_int_t
ngx_http_cache_turbo_name_has_suffix(u_char *n, size_t nlen, const char *suffix)
{
    size_t  slen;

    slen = ngx_strlen(suffix);

    if (slen == 0 || nlen < slen) {
        return 0;
    }

    return ngx_strncmp(n + (nlen - slen), suffix, slen) == 0;
}


/* Phase 1 of ngx_http_cache_turbo_cookie_pred_one(): locate the next
 * ';'-separated pair starting at *pp (bounded by end), OWS-trim it, and
 * advance *pp past it so the caller's loop can call this again for the next
 * pair. Returns the trimmed pair in the name/plen out-params. Returns 0 when the pair
 * was empty ("; ;") or the scan hit `end` with nothing left — the caller
 * must `continue`/`break` its loop on that value without reading *namep or
 * *plenp, exactly as the inline loop this replaces did. Returns 1 when a
 * non-empty pair was produced. */
static ngx_int_t
ngx_http_cache_turbo_cookie_pred_one_next_pair(u_char **pp, u_char *end,
    u_char **namep, size_t *plenp)
{
    u_char  *p, *name;
    size_t   plen;

    p = *pp;

    /* Skip leading OWS and stray ';' before this pair. */
    while (p < end && (*p == ' ' || *p == '\t' || *p == ';')) {
        p++;
    }
    if (p >= end) {
        *pp = p;
        return 0;
    }

    /* The pair runs to the next ';' or to the end of the header value. */
    name = p;
    while (p < end && *p != ';') {
        p++;
    }
    plen = (size_t) (p - name);

    /* Trim trailing OWS off the pair. */
    while (plen > 0 && (name[plen - 1] == ' ' || name[plen - 1] == '\t')) {
        plen--;
    }

    *pp = p;

    if (plen == 0) {
        return 0;                           /* empty pair ("; ;") — ignore */
    }

    *namep = name;
    *plenp = plen;
    return 1;
}


/* Phase 2 of ngx_http_cache_turbo_cookie_pred_one(): split one OWS-trimmed
 * pair [name, name+plen) on '=' and test the name against pr->name_suffix.
 * Returns NGX_ERROR when the name does not match (caller must `continue`,
 * reading no out-param). Returns NGX_DECLINED when the name matches but the
 * pair is bare (no '=') — this is the fail-closed "unparseable => bypass"
 * case, and the caller must return 1 immediately without reading *valp/
 * *vlenp. Returns NGX_OK when the name matches and a value was split out
 * into the value/vlen out-params for the op dispatch that follows. */
static ngx_int_t
ngx_http_cache_turbo_cookie_pred_one_split(u_char *name, size_t plen,
    const ngx_http_cache_turbo_cookie_pred_t *pr, u_char **valp, size_t *vlenp)
{
    u_char  *eq, *val;
    size_t   nlen;

    /* Split name '=' value, bounded by plen (no NUL to lean on). */
    eq = ngx_strlchr(name, name + plen, '=');

    if (eq == NULL) {
        /* A bare cookie with no '='. If its NAME is the one we key on, we
         * cannot read a value and must not guess: fail closed to bypass. */
        nlen = plen;
        while (nlen > 0 && (name[nlen - 1] == ' ' || name[nlen - 1] == '\t')) {
            nlen--;
        }
        if (ngx_http_cache_turbo_name_has_suffix(name, nlen,
                                                 pr->name_suffix))
        {
            return NGX_DECLINED;            /* unparseable => bypass */
        }
        return NGX_ERROR;                   /* different cookie */
    }

    nlen = (size_t) (eq - name);
    while (nlen > 0 && (name[nlen - 1] == ' ' || name[nlen - 1] == '\t')) {
        nlen--;                              /* OWS before '=' */
    }

    if (!ngx_http_cache_turbo_name_has_suffix(name, nlen, pr->name_suffix)) {
        return NGX_ERROR;                    /* different cookie */
    }

    /* Value = everything after '=' to the end of the pair, OWS-trimmed. */
    val = eq + 1;
    while (val < name + plen && (*val == ' ' || *val == '\t')) {
        val++;
    }

    *valp = val;
    *vlenp = (size_t) ((name + plen) - val);
    return NGX_OK;
}


/* Phase 3 of ngx_http_cache_turbo_cookie_pred_one(): apply pr->op to one
 * already-matched cookie value. Returns 1 = this pair decides bypass (the
 * caller must return immediately), 0 = this pair has no opinion (the caller
 * must `continue` its scan — see the comment at the call site on why a
 * "cacheable" answer from one pair must not end the scan). Arm order and
 * short-circuit behaviour are unchanged from the inline switch: NONEMPTY,
 * then EQ, then NE/default, each returning before any later arm is reached. */
static ngx_int_t
ngx_http_cache_turbo_cookie_pred_one_dispatch(u_char *val, size_t vlen,
    const ngx_http_cache_turbo_cookie_pred_t *pr)
{
    size_t  cmplen;

    /* cmplen is deliberately NOT plen: plen was this pair's length and only
     * bounded `val` in the split phase. Reusing it for the predicate value's
     * length is safe only for as long as every arm returns. */
    cmplen = (pr->value != NULL) ? ngx_strlen(pr->value) : 0;

    switch (pr->op) {

    case NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY:
        if (vlen > 0) {
            return 1;
        }
        return 0;

    case NGX_HTTP_CACHE_TURBO_CVOP_EQ:
        /* A value-comparing op with no literal cannot match anything. Guard
         * it: the registry never ships such a row, but the compare below
         * passes pr->value to a nonnull parameter. */
        if (pr->value != NULL
            && vlen == cmplen
            && ngx_strncmp(val, pr->value, cmplen) == 0)
        {
            return 1;
        }
        return 0;

    case NGX_HTTP_CACHE_TURBO_CVOP_NE:
    default:
        /* The phpBB case. An EMPTY value ("_u=") is not the guest literal
         * "1", so by the letter of != it is a member — but it is really a
         * malformed/cleared cookie. Bypass either way: both readings agree,
         * and bypass is the safe direction. */
        if (pr->value != NULL
            && vlen == cmplen
            && ngx_strncmp(val, pr->value, cmplen) == 0)
        {
            return 0;                        /* == the guest literal: cacheable */
        }
        return 1;                            /* anything else (incl. a row with
                                              * no literal): bypass, the safe
                                              * direction */
    }
}


/*
 * Evaluate one predicate against one Cookie header value (which may itself hold
 * several ';'-separated pairs). Returns 1 = request is dynamic (bypass), 0 = no
 * opinion. "No opinion" is NOT "cacheable": the caller ORs the results of every
 * predicate of every active preset, and a request nothing objects to is cached.
 * A predicate whose cookie is ABSENT must therefore return 0 — for phpBB that is
 * correct, since a visitor with no _u at all has no session and is a guest.
 */
static ngx_int_t
ngx_http_cache_turbo_cookie_pred_one(u_char *data, size_t len,
    const ngx_http_cache_turbo_cookie_pred_t *pr)
{
    u_char      *p, *end, *name, *val;
    size_t       plen, vlen;
    ngx_int_t    rc;

    /* An empty (or absent) Cookie value: nothing to match, and no opinion. The
     * explicit guard is required, not cosmetic — a header can carry data == NULL
     * with len == 0, and computing `data + len` on a NULL pointer is undefined
     * behaviour even when the offset is zero (UBSan: "applying zero offset to
     * null pointer"). The fuzzer hit this on its first empty input. */
    if (data == NULL || len == 0) {
        return 0;
    }

    p = data;
    end = data + len;

    while (p < end) {

        if (!ngx_http_cache_turbo_cookie_pred_one_next_pair(&p, end, &name,
                                                             &plen))
        {
            continue;                        /* empty pair, or scan exhausted */
        }

        rc = ngx_http_cache_turbo_cookie_pred_one_split(name, plen, pr,
                                                         &val, &vlen);
        if (rc == NGX_ERROR) {
            continue;                        /* different cookie */
        }
        if (rc == NGX_DECLINED) {
            return 1;                        /* unparseable => bypass */
        }

        /* A "this pair says cacheable" answer must NOT end the scan: the header
         * can carry several cookies whose names all end in the suffix (phpBB
         * keys on `_u`, and `phpbb3_<hash>_u` is per-board, so one browser
         * visiting two boards on the same host sends two of them). Whichever
         * one comes first would otherwise decide for the whole request, and a
         * leading guest `_u=1` would mask a member `_u=42` behind it — serving
         * and storing that member's page. So only `continue` here; bypass (1)
         * still returns immediately, and "no pair objected" is the loop's exit
         * value below. */
        if (ngx_http_cache_turbo_cookie_pred_one_dispatch(val, vlen, pr)) {
            return 1;
        }
    }

    return 0;                                /* cookie absent: no opinion */
}


/* True if any predicate in the NULL-terminated list fires against any Cookie
 * header on the request. */
static ngx_int_t
ngx_http_cache_turbo_cookie_pred(ngx_http_request_t *r,
    const ngx_http_cache_turbo_cookie_pred_t *preds)
{
    const ngx_http_cache_turbo_cookie_pred_t  *pr;
#if (nginx_version >= 1023000)
    ngx_table_elt_t                           *ck;

    for (pr = preds; pr->name_suffix; pr++) {
        for (ck = r->headers_in.cookie; ck; ck = ck->next) {
            if (ngx_http_cache_turbo_cookie_pred_one(ck->value.data,
                                                     ck->value.len, pr))
            {
                return 1;
            }
        }
    }
#else
    ngx_table_elt_t                          **ckp;
    ngx_uint_t                                 i;

    ckp = r->headers_in.cookies.elts;
    for (pr = preds; pr->name_suffix; pr++) {
        for (i = 0; i < r->headers_in.cookies.nelts; i++) {
            if (ngx_http_cache_turbo_cookie_pred_one(ckp[i]->value.data,
                                                     ckp[i]->value.len, pr))
            {
                return 1;
            }
        }
    }
#endif
    return 0;
}
#endif /* NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO */


#if defined(NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO)
/*
 * Extract the VALUE of one cookie from one Cookie header value, by EXACT name.
 * Returns 1 and fills *val when the cookie is present, 0 otherwise. A present
 * cookie with an empty or absent value yields a zero-length *val and still
 * returns 1 — "present but empty" is a distinct key from "absent", and both are
 * distinct from any real value.
 *
 * EXACT name, not the suffix rule the predicate engine uses. A key cookie is
 * shipped by the application under a fixed name (X-Magento-Vary), and the name
 * bounds a value that goes into the CACHE KEY: a loose match would let an
 * attacker-chosen cookie ("NOT-X-Magento-Vary") select which bucket a victim's
 * request lands in. The predicate engine can afford suffix matching because its
 * failure direction is a needless bypass; keying cannot.
 */
static ngx_int_t
ngx_http_cache_turbo_cookie_value(u_char *data, size_t len, const char *name,
    size_t nmlen, ngx_str_t *val)
{
    u_char  *p, *end, *pair, *eq, *v;
    size_t   plen, nlen;

    /* NULL data with len == 0: `data + len` is UB even at zero offset. */
    if (data == NULL || len == 0) {
        return 0;
    }

    p = data;
    end = data + len;

    while (p < end) {

        while (p < end && (*p == ' ' || *p == '\t' || *p == ';')) {
            p++;
        }
        if (p >= end) {
            break;
        }

        pair = p;
        while (p < end && *p != ';') {
            p++;
        }
        plen = (size_t) (p - pair);

        while (plen > 0 && (pair[plen - 1] == ' ' || pair[plen - 1] == '\t')) {
            plen--;
        }
        if (plen == 0) {
            continue;
        }

        eq = ngx_strlchr(pair, pair + plen, '=');

        if (eq == NULL) {
            /* Bare cookie, no '='. If it is ours, it is present with no value. */
            nlen = plen;
            while (nlen > 0 && (pair[nlen - 1] == ' ' || pair[nlen - 1] == '\t')) {
                nlen--;
            }
            if (nlen == nmlen && ngx_strncmp(pair, name, nmlen) == 0) {
                val->data = pair;
                val->len = 0;
                return 1;
            }
            continue;
        }

        nlen = (size_t) (eq - pair);
        while (nlen > 0 && (pair[nlen - 1] == ' ' || pair[nlen - 1] == '\t')) {
            nlen--;
        }

        if (nlen != nmlen || ngx_strncmp(pair, name, nmlen) != 0) {
            continue;
        }

        v = eq + 1;
        while (v < pair + plen && (*v == ' ' || *v == '\t')) {
            v++;
        }
        val->data = v;
        val->len = (size_t) ((pair + plen) - v);
        return 1;
    }

    return 0;
}
#endif /* NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO */


#if !defined(NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO)
static ngx_int_t
ngx_http_cache_turbo_cookie_index_add(ngx_http_request_t *r,
    ngx_http_cache_turbo_cookie_index_t *idx, u_char *name, size_t nlen,
    u_char *value, size_t vlen, ngx_uint_t bare)
{
    ngx_http_cache_turbo_cookie_pair_t  *p, *expanded;
    ngx_uint_t                           i;

    for (i = 0; i < idx->npairs; i++) {
        p = &idx->pairs[i];
        if (p->name.len == nlen
            && ngx_strncmp(p->name.data, name, nlen) == 0)
        {
            return NGX_OK;              /* first occurrence wins */
        }
    }

    if (idx->npairs == idx->cap) {
        if (idx->cap > NGX_MAX_SIZE_T_VALUE
                       / (2 * sizeof(ngx_http_cache_turbo_cookie_pair_t)))
        {
            return NGX_ERROR;
        }

        expanded = ngx_palloc(r->pool,
                              idx->cap * 2
                              * sizeof(ngx_http_cache_turbo_cookie_pair_t));
        if (expanded == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(expanded, idx->pairs,
                   idx->npairs
                   * sizeof(ngx_http_cache_turbo_cookie_pair_t));
        idx->pairs = expanded;
        idx->cap *= 2;
    }

    p = &idx->pairs[idx->npairs++];
    p->name.data = name;
    p->name.len = nlen;
    p->value.data = value;
    p->value.len = vlen;
    p->bare = bare ? 1 : 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_cache_turbo_cookie_index_parse_one(ngx_http_request_t *r,
    ngx_http_cache_turbo_cookie_index_t *idx, u_char *data, size_t len)
{
    u_char  *p, *end, *pair, *eq, *v;
    size_t   plen, nlen;

    if (data == NULL || len == 0) {
        return NGX_OK;
    }

    p = data;
    end = data + len;

    while (p < end) {
        while (p < end && (*p == ' ' || *p == '\t' || *p == ';')) {
            p++;
        }
        if (p >= end) {
            break;
        }

        pair = p;
        while (p < end && *p != ';') {
            p++;
        }
        plen = (size_t) (p - pair);

        while (plen > 0 && (pair[plen - 1] == ' ' || pair[plen - 1] == '\t')) {
            plen--;
        }
        if (plen == 0) {
            continue;
        }

        eq = ngx_strlchr(pair, pair + plen, '=');

        if (eq == NULL) {
            nlen = plen;
            while (nlen > 0
                   && (pair[nlen - 1] == ' ' || pair[nlen - 1] == '\t'))
            {
                nlen--;
            }

            if (ngx_http_cache_turbo_cookie_index_add(r, idx, pair, nlen,
                                                      pair, 0, 1)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
            continue;
        }

        nlen = (size_t) (eq - pair);
        while (nlen > 0 && (pair[nlen - 1] == ' ' || pair[nlen - 1] == '\t')) {
            nlen--;
        }

        v = eq + 1;
        while (v < pair + plen && (*v == ' ' || *v == '\t')) {
            v++;
        }

        if (ngx_http_cache_turbo_cookie_index_add(r, idx, pair, nlen, v,
                                                  (size_t) ((pair + plen) - v),
                                                  0)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_http_cache_turbo_cookie_index_t *
ngx_http_cache_turbo_cookie_index(ngx_http_request_t *r)
{
    ngx_http_cache_turbo_ctx_t          *ctx;
    ngx_http_cache_turbo_cookie_index_t *idx;
#if (nginx_version >= 1023000)
    ngx_table_elt_t                     *ck;
#else
    ngx_table_elt_t                    **ckp;
    ngx_uint_t                           i;
#endif

    ctx = ngx_http_get_module_ctx(r, ngx_http_cache_turbo_module);
    if (ctx == NULL) {
        return NULL;
    }

    idx = &ctx->cookie_index;
    if (ctx->cookie_index_built) {
        return idx;
    }

    idx->pairs = idx->inline_pairs;
    idx->npairs = 0;
    idx->cap = sizeof(idx->inline_pairs) / sizeof(idx->inline_pairs[0]);

#if (nginx_version >= 1023000)
    for (ck = r->headers_in.cookie; ck; ck = ck->next) {
        if (ngx_http_cache_turbo_cookie_index_parse_one(r, idx,
                                                        ck->value.data,
                                                        ck->value.len)
            != NGX_OK)
        {
            return NULL;
        }
    }
#else
    ckp = r->headers_in.cookies.elts;
    for (i = 0; i < r->headers_in.cookies.nelts; i++) {
        if (ngx_http_cache_turbo_cookie_index_parse_one(r, idx,
                                                        ckp[i]->value.data,
                                                        ckp[i]->value.len)
            != NGX_OK)
        {
            return NULL;
        }
    }
#endif

    ctx->cookie_index_built = 1;
    return idx;
}


static ngx_int_t
ngx_http_cache_turbo_cookie_index_lookup(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *val_out)
{
    ngx_http_cache_turbo_cookie_index_t *idx;
    ngx_http_cache_turbo_cookie_pair_t  *p;
    ngx_uint_t                           i;

    idx = ngx_http_cache_turbo_cookie_index(r);
    if (idx == NULL) {
        return 0;
    }

    p = idx->pairs;
    for (i = 0; i < idx->npairs; i++) {
        if (p[i].name.len == name->len
            && ngx_strncmp(p[i].name.data, name->data, name->len) == 0)
        {
            *val_out = p[i].value;
            return 1;
        }
    }

    return 0;
}


static ngx_int_t
ngx_http_cache_turbo_cookie_pred_index_match(ngx_http_request_t *r,
    ngx_array_t *preds)
{
    ngx_http_cache_turbo_cookie_index_t       *idx;
    ngx_http_cache_turbo_cookie_pair_t        *p;
    ngx_http_cache_turbo_auto_cookie_pred_t   *pr;
    ngx_uint_t                                 i, j;

    if (preds == NULL || preds->nelts == 0) {
        return 0;
    }

    idx = ngx_http_cache_turbo_cookie_index(r);
    if (idx == NULL) {
        return 1;                       /* fail closed */
    }

    p = idx->pairs;
    pr = preds->elts;

    for (i = 0; i < idx->npairs; i++) {
        for (j = 0; j < preds->nelts; j++) {
            if (pr[j].name_suffix.len == 0
                || p[i].name.len < pr[j].name_suffix.len
                || ngx_strncmp(p[i].name.data
                               + (p[i].name.len - pr[j].name_suffix.len),
                               pr[j].name_suffix.data,
                               pr[j].name_suffix.len) != 0)
            {
                continue;
            }

            if (p[i].bare) {
                return 1;               /* matched name with no value */
            }

            switch (pr[j].op) {
            case NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY:
                if (p[i].value.len > 0) {
                    return 1;
                }
                break;

            case NGX_HTTP_CACHE_TURBO_CVOP_EQ:
                if (pr[j].has_value
                    && p[i].value.len == pr[j].value.len
                    && ngx_strncmp(p[i].value.data, pr[j].value.data,
                                   pr[j].value.len) == 0)
                {
                    return 1;
                }
                break;

            case NGX_HTTP_CACHE_TURBO_CVOP_NE:
            default:
                if (!pr[j].has_value
                    || p[i].value.len != pr[j].value.len
                    || ngx_strncmp(p[i].value.data, pr[j].value.data,
                                   pr[j].value.len) != 0)
                {
                    return 1;
                }
                break;
            }
        }
    }

    return 0;
}
#endif /* !NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO */


/*
 * URI prefix match with a PATH-SEGMENT BOUNDARY. A preset URI rule like "/user"
 * must bypass "/user" and "/user/settings" but NOT "/users-guide" — a bare
 * ngx_strncmp prefix test matches all three and silently over-bypasses (a
 * hit-rate loss) or, worse for a slash-less rule that is a genuine prefix of an
 * unrelated public path, un-caches real content.
 *
 * A match requires the prefix, and then the URI must either END or continue with
 * a boundary byte. Boundary bytes are '/' AND '.': '.' matters because Rails-
 * style backends serve the same controller action with a format suffix appended
 * directly to the path ("/notifications" -> "/notifications.json"), and those
 * suffixed variants are the DYNAMIC endpoint we must keep bypassing. Requiring
 * only '/' would un-bypass "/notifications.json" and leak it. Note r->uri never
 * contains the query string (nginx splits it into r->args), so '/' and '.' are
 * the only boundaries that occur.
 *
 * Rules that already carry their own boundary (a trailing '/' like "/wp-admin/",
 * or a file suffix like "/xmlrpc.php") are unaffected: the byte after the prefix
 * is fixed by the needle itself, so the extra check is always satisfied.
 */
static ngx_int_t
ngx_http_cache_turbo_uri_prefix(ngx_str_t *uri, const char *pfx, size_t l)
{
    u_char  next;

    if (uri->len < l || ngx_strncmp(uri->data, pfx, l) != 0) {
        return 0;
    }

    if (uri->len == l) {
        return 1;                       /* exact match: "/panel" == "/panel" */
    }

    /* A needle that already ends in a boundary ("/wp-admin/") carries its own
     * segment terminator: any continuation is inside the matched subtree, so a
     * plain prefix is the whole test. Only slash-less needles ("/panel") need
     * the trailing byte checked. */
    if (pfx[l - 1] == '/') {
        return 1;
    }

    next = uri->data[l];
    return (next == '/' || next == '.');
}


#if !defined(NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO)
static ngx_http_cache_turbo_uri_edge_t *
ngx_http_cache_turbo_uri_edge_find(ngx_http_cache_turbo_uri_node_t *node,
    u_char ch)
{
    ngx_http_cache_turbo_uri_edge_t  *e;

    for (e = node->edges; e != NULL; e = e->sibling) {
        if (e->ch == ch) {
            return e;
        }
    }

    return NULL;
}


static ngx_int_t
ngx_http_cache_turbo_uri_trie_match(ngx_http_cache_turbo_uri_node_t *root,
    ngx_str_t *uri)
{
    ngx_http_cache_turbo_uri_node_t  *node;
    ngx_http_cache_turbo_uri_edge_t  *edge;
    ngx_uint_t                        i;
    u_char                            next;

    if (root == NULL) {
        return 0;
    }

    node = root;

    for (i = 0; i < uri->len; i++) {
        edge = ngx_http_cache_turbo_uri_edge_find(node, uri->data[i]);
        if (edge == NULL) {
            return 0;
        }

        node = edge->next;

        if (!node->terminal) {
            continue;
        }

        if (node->slash_terminal || i + 1 == uri->len) {
            return 1;
        }

        next = uri->data[i + 1];
        if (next == '/' || next == '.') {
            return 1;
        }
    }

    return 0;
}
#endif /* !NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO */


/* One hex nibble -> 0..15, or -1 on a non-hex char. Lives inside the
 * FUZZ-EXTRACT region because the query-string decoder below needs it; the
 * hex-decode helpers further down share it. */
ngx_int_t
ngx_http_cache_turbo_hexval(u_char c)
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    return -1;
}


/*
 * Compare one raw query-string span against a plain needle, percent-DECODING
 * the span as it goes.
 *
 * The backend routes on the decoded query string: PHP's $_GET turns "%61ction"
 * into "action" and "log%69n" into "login", and every forum family in the
 * preset table routes that way. Comparing the raw bytes therefore misses a
 * request the backend treats as identical to one the classifier does catch, so
 * an over-encoded (or deliberately encoded) login/logout/PM URL is classified
 * cacheable and gets stored. Decoding as we compare needs no buffer and no
 * length cap, so a megabyte-long value costs one walk and nothing else.
 *
 * Malformed escapes ("%", "%A", "%GG") compare as a literal '%' followed by
 * whatever follows it, which is how PHP's parser leaves them.
 *
 * `name` selects PHP's key mangling, and only argument NAMES get it. PHP builds
 * $_GET keys through php_register_variable_ex(), which rewrites '.' and ' ' to
 * '_' — a habit inherited from register_globals, where a key had to be a legal
 * variable name. So "%2ExfToken", "xf+Token" and "ips4.hasJS" all arrive at the
 * application as "_xfToken" / "xf_Token" / "ips4_hasJS", and a matcher that
 * only percent-decodes misses every one of them. Underscores are common in the
 * needles (_xfToken, api_key, ips4_theme, woocommerce_cart_hash), so this is
 * the same fail-open as the encoding case, one alphabet further out.
 *
 * A LITERAL '+' is a space here (form encoding), so it mangles to '_' too; a
 * percent-escaped one ("%2B") decodes to a real '+' and PHP leaves it alone, so
 * the two are tracked apart. PHP additionally strips leading spaces from a key,
 * which this does not — a leading space folds to '_' instead. That direction
 * over-matches (an unnecessary bypass, hit rate only) where the alternative
 * would under-match, which is a cached private page.
 *
 * VALUES are never mangled by PHP and are not mangled here. A '+' in a value
 * stays a '+': every needle value is a fixed route token with no space in it,
 * so no treatment of '+' can create or destroy a match.
 */
static ngx_int_t
ngx_http_cache_turbo_qs_eq(u_char *p, u_char *end, const char *needle,
    size_t nlen, ngx_uint_t name)
{
    size_t     i;
    u_char     c;
    ngx_int_t  hi, lo, decoded;

    for (i = 0; p < end; i++) {

        c = *p++;
        decoded = 0;

        if (c == '%' && (size_t) (end - p) >= 2
            && (hi = ngx_http_cache_turbo_hexval(p[0])) >= 0
            && (lo = ngx_http_cache_turbo_hexval(p[1])) >= 0)
        {
            c = (u_char) ((hi << 4) | lo);
            p += 2;
            decoded = 1;
        }

        if (name) {
            if (c == '+' && !decoded) {
                c = '_';                /* literal '+' is a space, and mangles */

            } else if (c == '.' || c == ' ') {
                c = '_';
            }
        }

        if (i >= nlen || c != (u_char) needle[i]) {
            return 0;
        }
    }

    return i == nlen;
}


/*
 * S231-PERF-AUTOCLASSIFY (args half): parse r->args ONCE per request instead
 * of once per needle. auto_skip() below loops every enabled preset's args[]
 * row (~109 needles across the registry today) and, before this change, each
 * one re-walked the ENTIRE query string from scratch via arg_match() — r->args
 * is client-controlled, so the cost of classifying one request scaled with
 * (query-string length) * (needle count), an attacker-amplified DoS surface
 * exactly like cookie_has()'s pre-bitset shape.
 *
 * ONE span array, built by a single linear pass, replaces the re-parse: each
 * entry records a NAME=VALUE (or bare NAME) pair's byte spans, split by the
 * SAME rules arg_match() always used (both '&' and ';' as separators, the
 * empty-pair "&&"/leading/trailing '&' skip, the no-'=' valueless case) --
 * see those rules' own comments below, unchanged and still authoritative.
 *
 * The first 64 spans stay inline. On the 65th non-empty pair, count the exact
 * remaining span total, allocate one request-pool array, copy the inline
 * prefix, and continue the same parse into it. This keeps ordinary requests
 * allocation-free without falling back to one whole-query rescan per enabled
 * needle at a client-controlled boundary. Allocation/size failure returns
 * NGX_ERROR to auto_skip(), which fails closed by classifying the request as
 * private/bypass; a partial span list is never consulted.
 *
 * A SECOND, independent first-byte presence set is built in the same pass,
 * keyed on each argument NAME's MANGLED first byte (the byte
 * ngx_http_cache_turbo_qs_eq() would compare at i=0), not the raw query-string
 * byte -- raw bytes would be WRONG here, unlike the cookie half's bitset:
 * qs_eq() percent-decodes and, for NAMES, folds '+' (literal, not %2B), '.'
 * and ' ' all to '_'. A raw-byte set built over r->args would therefore MISS
 * '_'-needle matches spelled ".xfToken", "+xfToken", " xfToken", "%5FxfToken"
 * or "%2ExfToken" -- a fail-open that caches a private response. Folding the
 * first byte the same way qs_eq() would is what keeps the set sound.
 *
 * PROOF this cannot fail open: if qs_eq(name_span, needle) returns 1 for some
 * pair, then by construction (the `i >= nlen || c != (u_char) needle[i]`
 * check at i=0, which qs_eq() performs BEFORE any later byte) the span's
 * first byte, decoded and name-mangled exactly as qs_eq() does it, equals
 * needle[0]. The set below is built by applying that identical decode+mangle
 * step to every recorded name span's first byte and setting its bit, so
 * needle[0]'s bit is set whenever any span could have matched it -- the set
 * is a superset of "needles reachable by some span", never a subset. A
 * needle is skipped only when its first byte's bit is ABSENT, i.e. only when
 * no recorded span's mangled first byte can equal it, i.e. only when qs_eq()
 * was certain to return 0 for every span against that needle. This holds
 * per-occurrence: with a repeated name ("action=profile&action=logout") both
 * spans are recorded and both contribute their (identical) first byte, so
 * repetition cannot suppress a bit either.
 *
 * nlen == 0 is guarded explicitly (skip is never applied) since qs_eq() with
 * an empty needle has no i=0 byte to compare and the "first byte" concept is
 * undefined; every real needle in the registry is a nonempty literal, so this
 * is defence, not a live path.
 *
 * All array indices below are (u_char)-cast before indexing the 256-entry
 * set, matching the cookie half's discipline -- a bare `char` is signed on
 * this platform's default and a high-bit byte would index out of bounds.
 *
 * Both tiers key off the NAME only (bare-NAME rules and NAME=VALUE rules
 * alike), so one span array + one first-byte set covers both.
 */
#define NGX_HTTP_CACHE_TURBO_ARGS_MAX  64

typedef struct {
    u_char  *name_start;
    u_char  *name_end;
    u_char  *value_start;               /* NULL => valueless ("?...&sid&...") */
    u_char  *value_end;
} ngx_http_cache_turbo_argspan_t;

typedef struct {
    ngx_http_cache_turbo_argspan_t  inline_spans[NGX_HTTP_CACHE_TURBO_ARGS_MAX];
    ngx_http_cache_turbo_argspan_t *spans;
    ngx_uint_t                      nspans;
    size_t                          capacity;
    u_char                          name_first[256]; /* mangled first-byte set */
} ngx_http_cache_turbo_argparse_t;

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
/* Test-only observable: counts qs_eq() NAME comparisons actually performed
 * by arg_match() across the whole request, mirroring the cookie half's
 * ngx_http_cache_turbo_test_cookie_scans counter -- a COUNTER oracle, never a
 * wall-clock timing band. Process-global; tests read a DELTA, never an
 * absolute value, and drive every probe of one oracle over one kept-alive
 * connection (nginx pins an accepted connection to one worker; each worker
 * owns its own copy of this global). */
ngx_atomic_uint_t  ngx_http_cache_turbo_test_arg_scans = 0;
#endif

/* Fold one raw (possibly percent-encoded) first byte the same way qs_eq()
 * would at i=0 for a NAME span: decode a valid %HH escape first, then apply
 * the name-mangling rule (literal '+' -> '_', '.' -> '_', ' ' -> '_'). `p`
 * must have at least one byte remaining (p < end checked by the caller). */
static u_char
ngx_http_cache_turbo_qs_first_mangled(u_char *p, u_char *end)
{
    u_char     c;
    ngx_int_t  hi, lo, decoded;

    c = *p++;
    decoded = 0;

    if (c == '%' && (size_t) (end - p) >= 2
        && (hi = ngx_http_cache_turbo_hexval(p[0])) >= 0
        && (lo = ngx_http_cache_turbo_hexval(p[1])) >= 0)
    {
        c = (u_char) ((hi << 4) | lo);
        decoded = 1;
    }

    if (c == '+' && !decoded) {
        c = '_';

    } else if (c == '.' || c == ' ') {
        c = '_';
    }

    return c;
}

/* Count non-empty pairs in [p,end). Used only after the inline span array
 * fills, so the common path remains one pass and allocation-free. This uses
 * the same separator/empty-pair rules as the recording pass below. */
static size_t
ngx_http_cache_turbo_argparse_tail_count(u_char *p, u_char *end)
{
    u_char  *pair;
    size_t   count;

    count = 0;

    while (p < end) {
        pair = p;

        while (p < end && *p != '&' && *p != ';') {
            p++;
        }

        if (p != pair) {
            count++;
        }

        if (p < end) {
            p++;
        }
    }

    return count;
}


/* Single linear recording pass over r->args: records every NAME (=VALUE)?
 * span and unions every NAME's mangled first byte into ap->name_first[]. The
 * overflow-only count above makes this two passes over the tail only when the
 * inline array fills; matching always remains one pass over cached spans. */
static ngx_int_t
ngx_http_cache_turbo_argparse_build(ngx_http_request_t *r,
    ngx_http_cache_turbo_argparse_t *ap)
{
    u_char                          *p, *end, *pair, *pend, *eq;
    ngx_http_cache_turbo_argspan_t *expanded;
    ngx_uint_t                      b;
    size_t                          remaining, capacity;

    ap->nspans = 0;
    ap->spans = ap->inline_spans;
    ap->capacity = NGX_HTTP_CACHE_TURBO_ARGS_MAX;

    for (b = 0; b < 256; b++) {
        ap->name_first[b] = 0;
    }

    if (r->args.data == NULL || r->args.len == 0) {
        return NGX_OK;
    }

    p = r->args.data;
    end = p + r->args.len;

    while (p < end) {

        pair = p;
        while (p < end && *p != '&' && *p != ';') {
            p++;
        }
        pend = p;

        if (p < end) {
            p++;                        /* step over the separator */
        }

        if (pend == pair) {
            continue;                   /* "&&", leading '&', trailing '&' */
        }

        eq = ngx_strlchr(pair, pend, '=');

        if (ap->nspans >= ap->capacity) {
            /* Only the inline array can fill: the pool allocation is sized
             * from this non-empty current pair through the exact tail. A
             * mismatch between the two identical walks still fails closed
             * here instead of writing past the allocation. */
            if (ap->spans != ap->inline_spans) {
                return NGX_ERROR;
            }

            remaining = ngx_http_cache_turbo_argparse_tail_count(pair, end);

            if (remaining > NGX_MAX_SIZE_T_VALUE
                            / sizeof(ngx_http_cache_turbo_argspan_t)
                            - ap->nspans)
            {
                return NGX_ERROR;
            }

            capacity = ap->nspans + remaining;
            expanded = ngx_palloc(r->pool,
                                  capacity
                                  * sizeof(ngx_http_cache_turbo_argspan_t));
            if (expanded == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(expanded, ap->inline_spans,
                       ap->nspans
                       * sizeof(ngx_http_cache_turbo_argspan_t));
            ap->spans = expanded;
            ap->capacity = capacity;
        }

        ap->spans[ap->nspans].name_start = pair;
        ap->spans[ap->nspans].name_end   = (eq != NULL) ? eq : pend;

        if (eq != NULL) {
            ap->spans[ap->nspans].value_start = eq + 1;
            ap->spans[ap->nspans].value_end   = pend;

        } else {
            ap->spans[ap->nspans].value_start = NULL;
            ap->spans[ap->nspans].value_end   = NULL;
        }

        ap->nspans++;

        /* Union this name's mangled first byte. nlen == 0 (an empty name,
         * "?=x" or "?&=x&") has no first byte to fold -- leave the set
         * untouched for it; qs_eq() against a nonempty needle already
         * returns 0 for an empty span via the `i >= nlen` check, so no
         * needle can legitimately match it and there is nothing to protect
         * by adding a bit here. */
        if (pair < ((eq != NULL) ? eq : pend)) {
            b = ngx_http_cache_turbo_qs_first_mangled(pair,
                                                       (eq != NULL) ? eq : pend);
            ap->name_first[(u_char) b] = 1;
        }
    }

    return NGX_OK;
}

/*
 * Scan the query string for an argument, and keep scanning past a non-match.
 *
 * Replaces ngx_http_arg() for preset classification. ngx_http_arg has two
 * properties that are wrong here:
 *
 *   1. It returns the FIRST occurrence of the name and stops. A query string
 *      may legally repeat a name ("?action=profile&action=logout"), and the
 *      backend decides which one wins — PHP's $_GET keeps the LAST. Stopping on
 *      the first meant an attacker prefixed a harmless value and the real
 *      dynamic route behind it was never seen, so the private page was cached.
 *      Every occurrence is checked here; any match is a match.
 *   2. It does not percent-decode, and it splits only on '&'. SMF and YaBB
 *      build nearly every multi-argument URL with ';' as the separator
 *      ("?action=profile;u=42"), a form PHP's arg_separator.input has accepted
 *      for its whole life — so with '&'-only splitting, only the first argument
 *      of such a URL was ever visible and the rest of those presets' arg rows
 *      matched nothing at all.
 *
 * `value == NULL` means the rule is a bare NAME and presence alone is the
 * signal (an empty "sid=" counts as present, matching ngx_http_arg). Otherwise
 * the decoded value must equal `value` exactly.
 *
 * Splitting on ';' can also split a value that carries an unescaped ';'
 * ("?next=/a;b"), which can only ever manufacture an EXTRA apparent argument.
 * That direction fails safe: the worst case is an unnecessary bypass (hit-rate
 * loss), never a cached private page.
 *
 * S231-PERF-AUTOCLASSIFY: `ap` is the request's complete pre-parsed span array
 * (see the builder above). A needle is skipped only when its first byte is
 * absent from ap->name_first[] -- see the byteset builder's proof for why that
 * cannot skip a needle qs_eq() would have matched.
 */
#if defined(NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO)
static ngx_int_t
ngx_http_cache_turbo_arg_match(const ngx_http_cache_turbo_argparse_t *ap,
    const char *name, size_t nlen, const char *value, size_t vlen)
{
    ngx_uint_t                              i;
    const ngx_http_cache_turbo_argspan_t   *sp;

    if (nlen > 0 && !ap->name_first[(u_char) name[0]]) {
        return 0;
    }

    for (i = 0; i < ap->nspans; i++) {
        sp = &ap->spans[i];

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
        ngx_atomic_fetch_add(&ngx_http_cache_turbo_test_arg_scans, 1);
#endif

        if (!ngx_http_cache_turbo_qs_eq(sp->name_start, sp->name_end,
                                         name, nlen, 1))
        {
            continue;
        }

        if (sp->value_start == NULL) {
            /* Valueless argument. Only a bare-NAME rule can match it. */
            if (value == NULL) {
                return 1;
            }
            continue;
        }

        if (value == NULL) {
            return 1;
        }

        if (ngx_http_cache_turbo_qs_eq(sp->value_start, sp->value_end,
                                        value, vlen, 0))
        {
            return 1;
        }
    }

    return 0;
}
#endif /* NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO */


#if !defined(NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO)
static ngx_int_t
ngx_http_cache_turbo_arg_rules_match(const ngx_http_cache_turbo_argparse_t *ap,
    ngx_array_t *rules)
{
    ngx_http_cache_turbo_auto_arg_rule_t  *ar;
    const ngx_http_cache_turbo_argspan_t  *sp;
    ngx_uint_t                             i, j;

    if (rules == NULL || rules->nelts == 0) {
        return 0;
    }

    ar = rules->elts;

    for (i = 0; i < ap->nspans; i++) {
        sp = &ap->spans[i];

        for (j = 0; j < rules->nelts; j++) {
            if (ar[j].name.len > 0
                && !ap->name_first[(u_char) ar[j].name.data[0]])
            {
                continue;
            }

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
            ngx_atomic_fetch_add(&ngx_http_cache_turbo_test_arg_scans, 1);
#endif

            if (!ngx_http_cache_turbo_qs_eq(sp->name_start, sp->name_end,
                                            (char *) ar[j].name.data,
                                            ar[j].name.len, 1))
            {
                continue;
            }

            if (!ar[j].has_value) {
                return 1;
            }

            if (sp->value_start == NULL) {
                continue;
            }

            if (ngx_http_cache_turbo_qs_eq(sp->value_start, sp->value_end,
                                           (char *) ar[j].value.data,
                                           ar[j].value.len, 0))
            {
                return 1;
            }
        }
    }

    return 0;
}
#endif /* !NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO */


/*
 * Auto-classify gate. Returns 1 when the request matches a dynamic surface of
 * any active preset (login/session cookie, backend URI prefix, dynamic query
 * arg) and must therefore skip the cache entirely (origin, never capture). 0 =
 * treat as cacheable and continue. Runs only when backend_presets != 0; sits
 * UNDER the manual bypass/no_store overrides (those are checked separately).
 */
ngx_int_t
ngx_http_cache_turbo_auto_skip(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf)
{
#if defined(NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO)
    const ngx_http_cache_turbo_preset_t  *ps;
    const char *const                    *pp;
    const char                           *eq;
    size_t                                l, nlen, vlen;
#else
    size_t                                l;
#endif
    ngx_str_t                             uri;
    ngx_http_cache_turbo_argparse_t       argparse;
#if defined(NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO)
    ngx_http_cache_turbo_byteset_t        cookie_bytes;
#endif

    /* S231-PERF-AUTOCLASSIFY (args half): parsed ONCE per request, reused by
     * arg_match() for every preset's args[] row below -- see the builder's
     * comment for the fail-safe overflow rule and the mangled-first-byte
     * correctness proof. An empty (or absent) query string yields nspans==0
     * and an all-zero name_first[], so every needle is skipped and
     * arg_match() returns 0, matching the pre-existing r->args.len==0 guard
     * exactly. */
    if (ngx_http_cache_turbo_argparse_build(r, &argparse) != NGX_OK) {
        return 1;                       /* fail closed: private / bypass */
    }

#if defined(NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO)
    /* S231-PERF-AUTOCLASSIFY (cookie half): built ONCE per request, unioned
     * over every Cookie header, and reused by cookie_has() for every preset
     * below -- see the byteset builder's correctness/bounded-work proof. An
     * empty (or absent) Cookie means an all-zero set. Aggregate Cookie values
     * over the fixed work cap, a null-backed nonempty value, or any sizing
     * ambiguity fail closed before a partial set can be consulted. */
    if (ngx_http_cache_turbo_cookie_byteset_build(r, &cookie_bytes) != NGX_OK) {
        return 1;                       /* fail closed: private / bypass */
    }
#endif

    /* Preset uris[] are literals anchored at byte 0 ("/wp-admin/"), so a
     * subdirectory install matches nothing unless we rebase the URI onto the
     * configured mount point. Loop-invariant, so computed once.
     *
     * The mount's trailing '/' is RETAINED as the rebased URI's leading '/':
     * "/shop/" over "/shop/wp-admin/" yields "/wp-admin/", which is the shape
     * every needle is written in. A URI outside the mount is left alone rather
     * than force-matched, so "/other/wp-admin/" on a "/shop/"-mounted site does
     * not inherit the mounted app's rules. */
    uri = r->uri;

    if (clcf->backend_prefix != NULL
        && clcf->backend_prefix != NGX_CONF_UNSET_PTR)
    {
        l = clcf->backend_prefix->len;

        if (uri.len >= l
            && ngx_strncmp(uri.data, clcf->backend_prefix->data, l) == 0)
        {
            uri.data += l - 1;          /* keep the mount's trailing '/' */
            uri.len  -= l - 1;
        }
    }

#if !defined(NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO)
    if (ngx_http_cache_turbo_uri_trie_match(clcf->auto_uri_root, &uri)) {
        return 1;
    }

    if (r->args.len
        && ngx_http_cache_turbo_arg_rules_match(&argparse,
                                                clcf->auto_arg_rules))
    {
        return 1;
    }

    if (ngx_http_cache_turbo_cookie_ac_match(r, &clcf->auto_cookie_ac)) {
        return 1;
    }

    if (ngx_http_cache_turbo_cookie_pred_index_match(r,
                                                     clcf->auto_cookie_preds))
    {
        return 1;
    }

#else
    for (ps = ngx_http_cache_turbo_presets; ps->bit; ps++) {
        if (!(clcf->backend_presets & ps->bit)) {
            continue;
        }

        for (pp = ps->uris; *pp; pp++) {
            l = ngx_strlen(*pp);
            if (ngx_http_cache_turbo_uri_prefix(&uri, *pp, l)) {
                return 1;
            }
        }

        if (r->args.len) {
            for (pp = ps->args; *pp; pp++) {
                eq = ngx_strchr(*pp, '=');

                if (eq == NULL) {
                    /* Bare NAME: presence of the argument is the signal,
                     * whatever its value ("_xfToken", "sid"). */
                    if (ngx_http_cache_turbo_arg_match(&argparse, *pp,
                                                       ngx_strlen(*pp), NULL, 0))
                    {
                        return 1;
                    }
                    continue;
                }

                /* NAME=VALUE: the forum families that route everything through
                 * one script ("index.php?action=login", "?do=compose") cannot
                 * be classified on the argument NAME — `action` and `do` also
                 * carry the ordinary read routes, so matching the bare name
                 * would bypass the whole board. Match the exact value instead.
                 * Values are fixed route tokens, so an exact byte compare is
                 * the whole test; no case folding, no prefix match. */
                nlen = (size_t) (eq - *pp);
                vlen = ngx_strlen(eq + 1);

                if (ngx_http_cache_turbo_arg_match(&argparse, *pp, nlen,
                                                   eq + 1, vlen))
                {
                    return 1;
                }
            }
        }

        if (ngx_http_cache_turbo_cookie_has(r, ps->cookies, &cookie_bytes)) {
            return 1;
        }

        /* Tier-2 value predicates. Only presets that cannot be classified by
         * cookie-name presence carry these (phpbb: <prefix>_u != ANONYMOUS). */
        if (ps->cookie_preds != NULL
            && ngx_http_cache_turbo_cookie_pred(r, ps->cookie_preds))
        {
            return 1;
        }
    }
#endif

    return 0;
}

#if defined(NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO)
ngx_int_t
ngx_http_cache_turbo_key_cookie(ngx_http_request_t *r,
    ngx_uint_t backend_presets, ngx_uint_t *cursor, ngx_str_t *name_out,
    ngx_str_t *val_out)
{
    const ngx_http_cache_turbo_preset_t  *ps;
    const char *const                    *pp;
    size_t                                nmlen;
    ngx_uint_t                            idx = 0;
    ngx_table_elt_t                      *ck;

    for (ps = ngx_http_cache_turbo_presets; ps->bit; ps++) {
        if (!(backend_presets & ps->bit) || ps->key_cookies == NULL) {
            continue;
        }

        for (pp = ps->key_cookies; *pp; pp++, idx++) {
            if (idx < *cursor) {
                continue;
            }

            nmlen = ngx_strlen(*pp);

            for (ck = r->headers_in.cookie; ck; ck = ck->next) {
                if (ngx_http_cache_turbo_cookie_value(ck->value.data,
                                                      ck->value.len,
                                                      *pp, nmlen, val_out))
                {
                    name_out->data = (u_char *) *pp;
                    name_out->len = nmlen;
                    *cursor = idx + 1;
                    return 1;
                }
            }
        }
    }

    *cursor = idx;
    return 0;
}
#endif /* NGX_HTTP_CACHE_TURBO_FUZZ_SHIM_AUTO */

/* >>> FUZZ-EXTRACT auto-classify END (match.c portion) <<< */

static ngx_int_t
ngx_http_cache_turbo_uri_trie_add(ngx_pool_t *pool,
    ngx_http_cache_turbo_uri_node_t *root, u_char *data, size_t len)
{
    ngx_http_cache_turbo_uri_node_t  *node, *next;
    ngx_http_cache_turbo_uri_edge_t  *edge;
    size_t                            i;

    node = root;

    for (i = 0; i < len; i++) {
        edge = ngx_http_cache_turbo_uri_edge_find(node, data[i]);
        if (edge == NULL) {
            edge = ngx_pcalloc(pool, sizeof(ngx_http_cache_turbo_uri_edge_t));
            if (edge == NULL) {
                return NGX_ERROR;
            }

            next = ngx_pcalloc(pool, sizeof(ngx_http_cache_turbo_uri_node_t));
            if (next == NULL) {
                return NGX_ERROR;
            }

            edge->ch = data[i];
            edge->next = next;
            edge->sibling = node->edges;
            node->edges = edge;
        }

        node = edge->next;
    }

    node->terminal = 1;
    if (len > 0 && data[len - 1] == '/') {
        node->slash_terminal = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_cache_turbo_auto_arg_rule_add(ngx_conf_t *cf,
    ngx_http_cache_turbo_loc_conf_t *clcf, const char *literal)
{
    ngx_http_cache_turbo_auto_arg_rule_t  *ar;
    u_char                                *p, *eq, *end;

    if (clcf->auto_arg_rules == NULL) {
        clcf->auto_arg_rules = ngx_array_create(cf->pool, 16,
                        sizeof(ngx_http_cache_turbo_auto_arg_rule_t));
        if (clcf->auto_arg_rules == NULL) {
            return NGX_ERROR;
        }
    }

    p = (u_char *) literal;
    end = p + ngx_strlen(literal);
    eq = ngx_strlchr(p, end, '=');

    ar = ngx_array_push(clcf->auto_arg_rules);
    if (ar == NULL) {
        return NGX_ERROR;
    }

    ar->name.data = p;
    ar->name.len = (eq == NULL) ? (size_t) (end - p) : (size_t) (eq - p);

    if (eq == NULL) {
        ngx_str_null(&ar->value);
        ar->has_value = 0;
    } else {
        ar->value.data = eq + 1;
        ar->value.len = (size_t) (end - (eq + 1));
        ar->has_value = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_cache_turbo_auto_str_array_add(ngx_conf_t *cf, ngx_array_t **array,
    const char *literal)
{
    ngx_str_t  *s;

    if (*array == NULL) {
        *array = ngx_array_create(cf->pool, 8, sizeof(ngx_str_t));
        if (*array == NULL) {
            return NGX_ERROR;
        }
    }

    s = ngx_array_push(*array);
    if (s == NULL) {
        return NGX_ERROR;
    }

    s->data = (u_char *) literal;
    s->len = ngx_strlen(literal);

    return NGX_OK;
}


static ngx_int_t
ngx_http_cache_turbo_auto_pred_add(ngx_conf_t *cf,
    ngx_http_cache_turbo_loc_conf_t *clcf,
    const ngx_http_cache_turbo_cookie_pred_t *pred)
{
    ngx_http_cache_turbo_auto_cookie_pred_t  *dst;

    if (clcf->auto_cookie_preds == NULL) {
        clcf->auto_cookie_preds = ngx_array_create(cf->pool, 4,
                        sizeof(ngx_http_cache_turbo_auto_cookie_pred_t));
        if (clcf->auto_cookie_preds == NULL) {
            return NGX_ERROR;
        }
    }

    dst = ngx_array_push(clcf->auto_cookie_preds);
    if (dst == NULL) {
        return NGX_ERROR;
    }

    dst->name_suffix.data = (u_char *) pred->name_suffix;
    dst->name_suffix.len = ngx_strlen(pred->name_suffix);
    dst->op = pred->op;

    if (pred->value == NULL) {
        ngx_str_null(&dst->value);
        dst->has_value = 0;
    } else {
        dst->value.data = (u_char *) pred->value;
        dst->value.len = ngx_strlen(pred->value);
        dst->has_value = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_cache_turbo_cookie_ac_prepare(ngx_http_cache_turbo_cookie_ac_t *ac,
    ngx_pool_t *pool, ngx_uint_t max_nodes)
{
    ngx_uint_t  i, j;

    if (max_nodes == 0) {
        ac->nodes = NULL;
        ac->nnodes = 0;
        ac->cap = 0;
        return NGX_OK;
    }

    if (max_nodes > NGX_MAX_SIZE_T_VALUE
                    / sizeof(ngx_http_cache_turbo_cookie_ac_node_t))
    {
        return NGX_ERROR;
    }

    ac->nodes = ngx_palloc(pool, max_nodes
                           * sizeof(ngx_http_cache_turbo_cookie_ac_node_t));
    if (ac->nodes == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < max_nodes; i++) {
        for (j = 0; j < 256; j++) {
            ac->nodes[i].next[j] = -1;
        }
        ac->nodes[i].fail = 0;
        ac->nodes[i].match = 0;
    }

    ac->nnodes = 1;
    ac->cap = max_nodes;
    return NGX_OK;
}


static ngx_int_t
ngx_http_cache_turbo_cookie_ac_insert(ngx_http_cache_turbo_cookie_ac_t *ac,
    u_char *data, size_t len)
{
    ngx_uint_t  state, next, i;
    u_char      c;

    if (ac->nodes == NULL || ac->nnodes == 0) {
        return NGX_ERROR;
    }

    if (len == 0) {
        ac->nodes[0].match = 1;
        return NGX_OK;
    }

    state = 0;

    for (i = 0; i < len; i++) {
        c = data[i];
        next = (ngx_uint_t) ac->nodes[state].next[c];

        if (ac->nodes[state].next[c] < 0) {
            if (ac->nnodes == ac->cap) {
                return NGX_ERROR;
            }
            next = ac->nnodes++;
            ac->nodes[state].next[c] = (ngx_int_t) next;
        }

        state = next;
    }

    ac->nodes[state].match = 1;
    return NGX_OK;
}


static ngx_int_t
ngx_http_cache_turbo_cookie_ac_finish(ngx_http_cache_turbo_cookie_ac_t *ac,
    ngx_pool_t *pool)
{
    ngx_uint_t  *queue, head, tail, state, fail, next, c;

    if (ac->nodes == NULL || ac->nnodes == 0) {
        return NGX_OK;
    }

    if (ac->nnodes > NGX_MAX_SIZE_T_VALUE / sizeof(ngx_uint_t)) {
        return NGX_ERROR;
    }

    queue = ngx_palloc(pool, ac->nnodes * sizeof(ngx_uint_t));
    if (queue == NULL) {
        return NGX_ERROR;
    }

    head = 0;
    tail = 0;

    for (c = 0; c < 256; c++) {
        next = (ngx_uint_t) ac->nodes[0].next[c];
        if (ac->nodes[0].next[c] < 0) {
            ac->nodes[0].next[c] = 0;
            continue;
        }

        ac->nodes[next].fail = 0;
        queue[tail++] = next;
    }

    while (head < tail) {
        state = queue[head++];

        for (c = 0; c < 256; c++) {
            if (ac->nodes[state].next[c] < 0) {
                ac->nodes[state].next[c] =
                    ac->nodes[ac->nodes[state].fail].next[c];
                continue;
            }

            next = (ngx_uint_t) ac->nodes[state].next[c];
            fail = (ngx_uint_t) ac->nodes[ac->nodes[state].fail].next[c];
            ac->nodes[next].fail = (ngx_int_t) fail;
            if (ac->nodes[fail].match) {
                ac->nodes[next].match = 1;
            }
            queue[tail++] = next;
        }
    }

    return NGX_OK;
}


char *
ngx_http_cache_turbo_compile_auto_presets(ngx_conf_t *cf,
    ngx_http_cache_turbo_loc_conf_t *clcf)
{
    const ngx_http_cache_turbo_preset_t       *ps;
    const ngx_http_cache_turbo_cookie_pred_t  *pr;
    const char *const                         *pp;
    ngx_uint_t                                 max_cookie_nodes;
    size_t                                     len;

    clcf->auto_uri_root = NULL;
    clcf->auto_arg_rules = NULL;
    clcf->auto_cookie_preds = NULL;
    clcf->auto_key_cookies = NULL;
    clcf->auto_cookie_ac.nodes = NULL;
    clcf->auto_cookie_ac.nnodes = 0;
    clcf->auto_cookie_ac.cap = 0;
    clcf->backend_key_cookies = 0;

    if (!NGX_HTTP_CACHE_TURBO_HAS_BACKEND(clcf->backend_presets)) {
        return NGX_CONF_OK;
    }

    max_cookie_nodes = 1;

    for (ps = ngx_http_cache_turbo_presets; ps->bit; ps++) {
        if (!(clcf->backend_presets & ps->bit)) {
            continue;
        }

        for (pp = ps->cookies; *pp; pp++) {
            len = ngx_strlen(*pp);
            if (len > (ngx_uint_t) -1 - max_cookie_nodes) {
                return NGX_CONF_ERROR;
            }
            max_cookie_nodes += (ngx_uint_t) len;
        }
    }

    if (ngx_http_cache_turbo_cookie_ac_prepare(&clcf->auto_cookie_ac, cf->pool,
                                               max_cookie_nodes)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    clcf->auto_uri_root = ngx_pcalloc(cf->pool,
                                      sizeof(ngx_http_cache_turbo_uri_node_t));
    if (clcf->auto_uri_root == NULL) {
        return NGX_CONF_ERROR;
    }

    for (ps = ngx_http_cache_turbo_presets; ps->bit; ps++) {
        if (!(clcf->backend_presets & ps->bit)) {
            continue;
        }

        for (pp = ps->uris; *pp; pp++) {
            len = ngx_strlen(*pp);
            if (ngx_http_cache_turbo_uri_trie_add(cf->pool,
                                                  clcf->auto_uri_root,
                                                  (u_char *) *pp, len)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
        }

        for (pp = ps->args; *pp; pp++) {
            if (ngx_http_cache_turbo_auto_arg_rule_add(cf, clcf, *pp)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
        }

        for (pp = ps->cookies; *pp; pp++) {
            len = ngx_strlen(*pp);
            if (ngx_http_cache_turbo_cookie_ac_insert(&clcf->auto_cookie_ac,
                                                      (u_char *) *pp, len)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
        }

        if (ps->cookie_preds != NULL) {
            for (pr = ps->cookie_preds; pr->name_suffix != NULL; pr++) {
                if (ngx_http_cache_turbo_auto_pred_add(cf, clcf, pr)
                    != NGX_OK)
                {
                    return NGX_CONF_ERROR;
                }
            }
        }

        if (ps->key_cookies != NULL) {
            for (pp = ps->key_cookies; *pp; pp++) {
                if (ngx_http_cache_turbo_auto_str_array_add(cf,
                        &clcf->auto_key_cookies, *pp)
                    != NGX_OK)
                {
                    return NGX_CONF_ERROR;
                }
                clcf->backend_key_cookies++;
            }
        }
    }

    if (ngx_http_cache_turbo_cookie_ac_finish(&clcf->auto_cookie_ac, cf->pool)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * Look the request's key cookie up across EVERY Cookie header. A client may
 * legally split its cookies over several Cookie headers, and Magento's own VCL
 * runs std.collect(req.http.Cookie) before it looks — without that, a request
 * that carries a decoy in the first header and the real cookie in the second
 * would key on the decoy, i.e. an attacker could CHOOSE which cache bucket to
 * read from or write to. Every header is scanned; the FIRST occurrence of the
 * name wins, which is the same rule a browser's own single header would give.
 *
 * This is an ITERATOR, not a single lookup. A preset may declare several key
 * cookies (and several presets may be enabled at once); returning only the
 * first present one made every cookie behind it dead — the key ignored it, so
 * two requests that differ only in that cookie shared an entry, which is the
 * cache leak the key cookie exists to prevent. The caller drives it to
 * exhaustion and folds EVERY present cookie into the key.
 *
 * *cursor must be 0 on the first call and is carried unchanged between calls;
 * it is the index (over the flattened enabled-preset x key-cookie sequence) of
 * the next candidate to examine. The sequence is walked from the start each
 * call — it is at most a dozen entries, and this keeps the iterator a pure
 * function of (request, presets, cursor).
 *
 * *name_out is set to the matched preset name so the key can record WHICH cookie
 * produced the value (two presets with key cookies must not produce the same key
 * suffix from different cookies). Returns 1 when a key cookie was found.
 */
ngx_int_t
ngx_http_cache_turbo_key_cookie(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_uint_t *cursor, ngx_str_t *name_out,
    ngx_str_t *val_out)
{
    ngx_str_t   *names;
    ngx_uint_t   i;

    if (clcf->auto_key_cookies == NULL || clcf->auto_key_cookies->nelts == 0) {
        *cursor = 0;
        return 0;
    }

    names = clcf->auto_key_cookies->elts;

    for (i = *cursor; i < clcf->auto_key_cookies->nelts; i++) {
        if (ngx_http_cache_turbo_cookie_index_lookup(r, &names[i], val_out)) {
            *name_out = names[i];
            *cursor = i + 1;
            return 1;
        }
    }

    *cursor = clcf->auto_key_cookies->nelts;
    return 0;
}


/*
 * DIY manual URI bypass (cache_turbo_bypass_uri). Returns 1 when r->uri matches
 * any configured prefix on a path-segment boundary, using the SAME matcher the
 * presets use (ngx_http_cache_turbo_uri_prefix) — so an app we ship no preset
 * for gets the identical subdirectory-safe bypass a preset URI rule would give,
 * with the same origin-and-never-capture treatment (the caller sets
 * ctx->auto_skip). Runs independently of backend_presets, so it works in pure
 * manual mode. Config-driven, so it lives OUTSIDE the fuzz-extracted preset
 * classifier. NULL / empty list => 0 (no cost when unused).
 */
ngx_int_t
ngx_http_cache_turbo_bypass_uri_match(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf)
{
    ngx_str_t   *pfx;
    ngx_uint_t   i;

    if (clcf->bypass_uri == NULL
        || clcf->bypass_uri == NGX_CONF_UNSET_PTR)
    {
        return 0;
    }

    pfx = clcf->bypass_uri->elts;
    for (i = 0; i < clcf->bypass_uri->nelts; i++) {
        if (ngx_http_cache_turbo_uri_prefix(&r->uri, (char *) pfx[i].data,
                                            pfx[i].len))
        {
            return 1;
        }
    }

    return 0;
}


/* S232-BYPASS-STALE: does r->uri opt in to breaker-only storage? Same
 * segment-boundary matcher as the bypass_uri walk above. */
ngx_uint_t
ngx_http_cache_turbo_bypass_stale_uri_match(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf)
{
    ngx_str_t   *pfx;
    ngx_uint_t   i;

    if (clcf->bypass_stale_uri == NULL
        || clcf->bypass_stale_uri == NGX_CONF_UNSET_PTR)
    {
        return 0;
    }

    pfx = clcf->bypass_stale_uri->elts;
    for (i = 0; i < clcf->bypass_stale_uri->nelts; i++) {
        if (ngx_http_cache_turbo_uri_prefix(&r->uri, (char *) pfx[i].data,
                                            pfx[i].len))
        {
            return 1;
        }
    }

    return 0;
}


/*
 * Config-driven cookie lookup for cache_turbo_key_cookie: find NAME's value
 * across EVERY Cookie header (same all-headers scan and first-occurrence-wins
 * rule as ngx_http_cache_turbo_key_cookie for the presets, and the same reason
 * — an attacker must not hide the real cookie in a second header to pick a
 * bucket). NAME comes from config (an ngx_str_t) rather than the preset's
 * NUL-terminated C string, so it is matched by explicit length. Returns 1 and
 * fills *val_out when found.
 */
ngx_int_t
ngx_http_cache_turbo_cookie_lookup(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *val_out)
{
    return ngx_http_cache_turbo_cookie_index_lookup(r, name, val_out);
}

#pragma GCC visibility pop
