/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Vary / variant / Accept-Encoding classification group (MAINT-SPLIT). Split
 * out of ngx_http_cache_turbo_module.c: query-arg denylist matching, the
 * Accept-Encoding class negotiation (zstd/br/gzip), device/language/origin
 * variant axes, the variant/marker digest helpers, the auto-Vary
 * prepare/apply pair, and the response Vary-header classifier that turns a
 * response's own Vary header into the same bit/nocache pair the request-side
 * helpers above compute proactively.
 *
 * ngx_http_cache_turbo_vary_suffix, _var_set, _name_denied and _tok_cmp stay
 * non-static because module.c's ngx_http_cache_turbo_normalized_args_variable
 * (kept in module.c: it lives in the $cache_turbo_normalized_args variable
 * registration block, not this classification group) calls them directly.
 * ngx_http_cache_turbo_vary_prepare, _vary_apply, _variant_hash, _marker_hash,
 * _marker_store, _variant_index_name, _classify_vary and _response_encoded
 * stay non-static for the same reason: module.c's access/header/body-filter
 * phases call them from many sites above this group's old position in the
 * file. ngx_http_cache_turbo_vary_prepare drops its `ngx_inline` — a cross-TU
 * call cannot stay inline. Every other function here (_pat_match,
 * _ae_q_ok, _ae_class_match_coding, _ae_class_dispatch, _ae_class,
 * _device_class, _req_header, _lang_class, and the three
 * classify_vary_* token helpers) is called only from within this group and
 * stays static.
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


/* ----- key normalize (v3-1) ------------------------------------------------ */

/* Built-in denylist: query params dropped from $cache_turbo_normalized_args by
 * default. A trailing '*' is a prefix match (so utm_* covers utm_source etc.).
 * cache_turbo_normalize_strip adds to this; it never removes a default. */
static ngx_str_t  ngx_http_cache_turbo_default_strip[] = {
    ngx_string("utm_*"),
    ngx_string("fbclid"),
    ngx_string("gclid"),
    ngx_string("msclkid"),
    ngx_string("mc_eid"),
    ngx_string("_ga"),
    ngx_string("ref"),
    ngx_string("sid"),
    ngx_string("sessionid"),
    ngx_string("tmp_*"),
};


/* Does an arg name match a denylist pattern? Trailing '*' => prefix match.
 * Case-insensitive: query-arg names reach here straight from r->args.data
 * (see ngx_http_cache_turbo_normalized_args_variable), never lowercased by
 * anything upstream, while every built-in and configured pattern is
 * lowercase -- so "UTM_Source" must still match "utm_*". */
static ngx_int_t
ngx_http_cache_turbo_pat_match(ngx_str_t *pat, u_char *name, size_t nlen)
{
    if (pat->len > 0 && pat->data[pat->len - 1] == '*') {
        size_t  plen = pat->len - 1;
        return nlen >= plen && ngx_strncasecmp(name, pat->data, plen) == 0;
    }
    return nlen == pat->len && ngx_strncasecmp(name, pat->data, nlen) == 0;
}


/* Set bit for byte `b` in a 256-bit (32-byte) bitmap. */
static ngx_inline void
ngx_http_cache_turbo_bitmap_set(u_char *bm, u_char b)
{
    bm[b >> 3] |= (u_char) (1 << (b & 7));
}


static ngx_inline ngx_int_t
ngx_http_cache_turbo_bitmap_get(const u_char *bm, u_char b)
{
    return (bm[b >> 3] & (1 << (b & 7))) != 0;
}


/* R3-3: precompute, at config-merge time, a 256-bit first-byte bitmap over
 * the combined denylist (built-in ngx_http_cache_turbo_default_strip[] plus
 * clcf->normalize_strip), so the per-request fast path in _name_denied can
 * reject a name whose first byte is on neither table with one bit test
 * instead of walking up to 10+N patterns and calling ngx_strncasecmp on each.
 *
 * Both cases of every pattern's first byte are set -- matching is
 * case-insensitive (see the comment on _pat_match) and names reach here
 * unlowercased. _pat_match treats a pattern as a match-everything wildcard
 * whenever its EFFECTIVE prefix length is 0: that is a genuinely
 * zero-length pattern (pat->len == 0), or the bare '*' produced by
 * `cache_turbo_normalize_strip *` (pat->len == 1, pat->data[0] == '*',
 * which _pat_match strips its trailing '*' from down to a zero-length
 * prefix). Either form matches nlen == 0 too, via `nlen >= plen`. Such a
 * pattern has no first byte of its own to gate on, so it sets
 * strip_bitmap_all instead of touching the bitmap; _name_denied must then
 * skip the bitmap short-circuit entirely and fall through to the full walk
 * (which _pat_match still resolves correctly), or every single-byte bitmap
 * check downstream would look wrong for a table that is not really
 * byte-selective any more. */
static ngx_inline ngx_int_t
ngx_http_cache_turbo_pat_is_wildcard_all(ngx_str_t *pat)
{
    return pat->len == 0
           || (pat->len == 1 && pat->data[0] == '*');
}


void
ngx_http_cache_turbo_build_strip_bitmap(ngx_http_cache_turbo_loc_conf_t *clcf)
{
    ngx_str_t   *pat;
    ngx_uint_t   i, n;
    u_char       b;

    ngx_memzero(clcf->strip_bitmap, sizeof(clcf->strip_bitmap));
    clcf->strip_bitmap_all = 0;

    n = sizeof(ngx_http_cache_turbo_default_strip) / sizeof(ngx_str_t);
    for (i = 0; i < n; i++) {
        pat = &ngx_http_cache_turbo_default_strip[i];

        if (ngx_http_cache_turbo_pat_is_wildcard_all(pat)) {
            clcf->strip_bitmap_all = 1;
            continue;
        }

        b = pat->data[0];
        ngx_http_cache_turbo_bitmap_set(clcf->strip_bitmap, ngx_tolower(b));
        ngx_http_cache_turbo_bitmap_set(clcf->strip_bitmap, ngx_toupper(b));
    }

    if (clcf->normalize_strip != NULL
        && clcf->normalize_strip != NGX_CONF_UNSET_PTR)
    {
        pat = clcf->normalize_strip->elts;
        for (i = 0; i < clcf->normalize_strip->nelts; i++) {
            if (ngx_http_cache_turbo_pat_is_wildcard_all(&pat[i])) {
                clcf->strip_bitmap_all = 1;
                continue;
            }

            b = pat[i].data[0];
            ngx_http_cache_turbo_bitmap_set(clcf->strip_bitmap,
                                             ngx_tolower(b));
            ngx_http_cache_turbo_bitmap_set(clcf->strip_bitmap,
                                             ngx_toupper(b));
        }
    }
}


/* Is this arg name on the denylist (built-in defaults + configured extras)?
 *
 * R3-3 fast path: clcf->strip_bitmap is a 256-bit first-byte bitmap over the
 * combined table, precomputed once at config-merge time by
 * ngx_http_cache_turbo_build_strip_bitmap(). nlen == 0 has no first byte to
 * gate on and falls straight through to the walk (it will only ever match a
 * zero-length wildcard pattern, which the walk still handles). Unless a
 * zero-length ("*") pattern is present -- strip_bitmap_all -- a name whose
 * first byte is not set in either case can match no pattern in the table
 * (every non-wildcard exact/prefix pattern requires nlen >= 1 and compares
 * byte 0 case-insensitively), so it is safe to reject before touching the
 * table at all. This does not change behaviour for any input: it only skips
 * calling _pat_match on entries that were always going to fail their own
 * first-byte comparison. */
ngx_int_t
ngx_http_cache_turbo_name_denied(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *name, size_t nlen)
{
    ngx_str_t   *pat;
    ngx_uint_t   i;

    if (!clcf->strip_bitmap_all
        && nlen > 0
        && !ngx_http_cache_turbo_bitmap_get(clcf->strip_bitmap, name[0]))
    {
        return 0;
    }

    for (i = 0;
         i < sizeof(ngx_http_cache_turbo_default_strip) / sizeof(ngx_str_t);
         i++)
    {
        if (ngx_http_cache_turbo_pat_match(
                &ngx_http_cache_turbo_default_strip[i], name, nlen))
        {
            return 1;
        }
    }

    if (clcf->normalize_strip != NULL
        && clcf->normalize_strip != NGX_CONF_UNSET_PTR)
    {
        pat = clcf->normalize_strip->elts;
        for (i = 0; i < clcf->normalize_strip->nelts; i++) {
            if (ngx_http_cache_turbo_pat_match(&pat[i], name, nlen)) {
                return 1;
            }
        }
    }

    return 0;
}


/* Stable byte-wise compare of two "name=value" tokens for the sort. */
ngx_int_t
ngx_http_cache_turbo_tok_cmp(const void *one, const void *two)
{
    const ngx_str_t  *a = one;
    const ngx_str_t  *b = two;
    size_t            n = ngx_min(a->len, b->len);
    ngx_int_t         rc = ngx_memcmp(a->data, b->data, n);

    if (rc != 0) {
        return rc;
    }
    return (ngx_int_t) a->len - (ngx_int_t) b->len;
}


/* ----- Vary-aware suffix (v3-4) --------------------------------------------- */

/* Per-coding q-value check for the Accept-Encoding parser. `p` points at the
 * first ';' of a coding token's parameters, `last` is the token end. Returns 0
 * iff an explicit `q=0` (0, 0.0, 0.000, …) is present — i.e. the client REFUSES
 * this coding — else 1 (a missing q, or any q>0, is acceptable). A bare substring
 * match would treat `gzip;q=0` as gzip-capable and re-key a never-gzip client
 * onto a gzip body (codex follow-up). RFC 9110 §12.5.3. */
static ngx_uint_t
ngx_http_cache_turbo_ae_q_ok(u_char *p, u_char *last)
{
    while (p < last) {
        if (*p != ';') {
            p++;
            continue;
        }
        p++;                                   /* past ';' */
        while (p < last && (*p == ' ' || *p == '\t')) {
            p++;
        }
        if (p + 1 < last && (p[0] == 'q' || p[0] == 'Q') && p[1] == '=') {
            ngx_uint_t  nonzero = 0;
            p += 2;
            while (p < last && *p != ';' && *p != ' ' && *p != '\t') {
                if (*p >= '1' && *p <= '9') {
                    nonzero = 1;
                }
                p++;
            }
            return nonzero ? 1 : 0;            /* q=0(.0…) => refused */
        }
    }
    return 1;                                  /* no q parameter => acceptable */
}


/* MAINT-H4f phase helper for ngx_http_cache_turbo_ae_class().
 * PHASE 1 -- match a trimmed coding name token against known algorithms and set flags.
 * The coding name (length clen) is matched case-insensitively by exact length against
 * {zstd, br, gzip}; a match sets *zstd, *br or *gzip to 1. No-op if clen does not
 * match any algorithm or the token does not match the bytes. */
static void
ngx_http_cache_turbo_ae_class_match_coding(u_char *tok, size_t clen,
    ngx_uint_t *zstd, ngx_uint_t *br, ngx_uint_t *gzip)
{
    if (clen == 4 && ngx_strncasecmp(tok, (u_char *) "zstd", 4) == 0) {
        *zstd = 1;
    } else if (clen == 2 && ngx_strncasecmp(tok, (u_char *) "br", 2) == 0) {
        *br = 1;
    } else if (clen == 4 && ngx_strncasecmp(tok, (u_char *) "gzip", 4) == 0) {
        *gzip = 1;
    }
}


/* MAINT-H4f phase helper for ngx_http_cache_turbo_ae_class().
 * PHASE 2 -- dispatch to the highest-priority accepted encoding.
 * Returns the encoding string for the first (highest-priority) algorithm that is set:
 * zstd > br > gzip > identity. Priority order matches what our stack serves. */
static ngx_str_t
ngx_http_cache_turbo_ae_class_dispatch(ngx_uint_t zstd, ngx_uint_t br,
    ngx_uint_t gzip)
{
    static ngx_str_t  zstd_s = ngx_string("zstd");
    static ngx_str_t  br_s = ngx_string("br");
    static ngx_str_t  gzip_s = ngx_string("gzip");
    static ngx_str_t  identity_s = ngx_string("identity");

    if (zstd) {
        return zstd_s;
    }
    if (br) {
        return br_s;
    }
    if (gzip) {
        return gzip_s;
    }
    return identity_s;
}


/* Accept-Encoding collapsed to a small, stable enum so the cache shards by what
 * the response actually IS (zstd/br/gzip/identity), not by the per-browser raw
 * header. Priority zstd > br > gzip mirrors what our stack serves when the client
 * accepts several: the http-zstd filter emits zstd whenever the client advertises
 * zstd (ngx_http_zstd_ok), winning over brotli/gzip, and brotli wins over gzip.
 * We ship http-zstd, so zstd MUST be bucketed or a zstd-only client could read an
 * identity entry and a zstd+br client could collide a zstd body under ae=br
 * (issues V6). Absent/empty header => identity.
 *
 * The header is tokenised on commas into full codings (each `coding[;params]`)
 * rather than substring-scanned, so `br` no longer matches inside `Calibre`,
 * `x-gzip` no longer aliases `gzip`, and a `;q=0` parameter de-selects the coding
 * (codex follow-up: token boundaries + q-values). Coding names are matched
 * case-insensitively at exact length. */
static ngx_str_t
ngx_http_cache_turbo_ae_class(ngx_http_request_t *r)
{
    ngx_table_elt_t  *ae = r->headers_in.accept_encoding;
    u_char           *p, *last, *end, *tok, *semi, *ce;
    size_t            clen;
    ngx_uint_t        zstd = 0, br = 0, gzip = 0;

    if (ae == NULL || ae->value.len == 0) {
        return ngx_http_cache_turbo_ae_class_dispatch(0, 0, 0);
    }

    p = ae->value.data;
    last = p + ae->value.len;

    while (p < last) {
        end = p;                               /* split on the next comma */
        while (end < last && *end != ',') {
            end++;
        }

        semi = p;                              /* coding name = [tok, semi) */
        while (semi < end && *semi != ';') {
            semi++;
        }

        tok = p;
        while (tok < semi && (*tok == ' ' || *tok == '\t')) {
            tok++;
        }
        ce = semi;
        while (ce > tok && (ce[-1] == ' ' || ce[-1] == '\t')) {
            ce--;
        }
        clen = (size_t) (ce - tok);

        if (clen > 0 && ngx_http_cache_turbo_ae_q_ok(semi, end)) {
            ngx_http_cache_turbo_ae_class_match_coding(tok, clen, &zstd, &br,
                &gzip);

            /* zstd is the top of the dispatch order below, so once it is set
             * no remaining token can change the answer -- stop parsing. Only
             * zstd allows this: seeing `br` first does NOT settle it, because
             * a later `zstd` would still outrank it. Accept-Encoding is
             * client-supplied and unbounded in token count, so this bounds the
             * common browser case (`gzip, deflate, br, zstd` -- zstd last, no
             * saving) as well as a deliberately long list that ends in, or
             * merely contains, zstd. */
            if (zstd) {
                break;
            }
        }

        p = (end < last) ? end + 1 : end;
    }

    return ngx_http_cache_turbo_ae_class_dispatch(zstd, br, gzip);
}


/* Device class from the User-Agent, coarse two-way bucket. Minimal substring
 * match for the standard mobile UA tokens (no regex: the module builds
 * --without-http_rewrite_module, no PCRE). Case-insensitive — core only ships a
 * bounded case-insensitive search (ngx_strlcasestrn); case-folding mobile tokens
 * is harmless. Tablets fall in desktop by design. */
static ngx_inline u_char
ngx_http_cache_turbo_lc_ascii(u_char c)
{
    return (u_char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c);
}


static ngx_uint_t
ngx_http_cache_turbo_match_lc(u_char *p, u_char *last, const char *needle,
    size_t nlen)
{
    size_t  i;

    if ((size_t) (last - p) < nlen) {
        return 0;
    }

    for (i = 1; i < nlen; i++) {
        if (ngx_http_cache_turbo_lc_ascii(p[i]) != (u_char) needle[i]) {
            return 0;
        }
    }

    return 1;
}


static ngx_str_t
ngx_http_cache_turbo_device_class(ngx_http_request_t *r)
{
    static ngx_str_t  desktop_s = ngx_string("desktop");
    static ngx_str_t  mobile_s = ngx_string("mobile");
    ngx_table_elt_t  *ua = r->headers_in.user_agent;
    u_char           *p, *last;

    if (ua == NULL || ua->value.len == 0) {
        return desktop_s;
    }

    p = ua->value.data;
    last = p + ua->value.len;

    for (; p < last; p++) {
        switch (ngx_http_cache_turbo_lc_ascii(*p)) {
        case 'm':
            if (ngx_http_cache_turbo_match_lc(p, last, "mobi", 4)) {
                return mobile_s;
            }
            break;
        case 'a':
            if (ngx_http_cache_turbo_match_lc(p, last, "android", 7)) {
                return mobile_s;
            }
            break;
        case 'i':
            if (ngx_http_cache_turbo_match_lc(p, last, "iphone", 6)) {
                return mobile_s;
            }
            break;
        default:
            break;
        }
    }

    return desktop_s;
}


/* Write the Vary suffix selected by the loc_conf bitmask into buf (>= MAX) and
 * return its byte length. Buckets are emitted in a FIXED order (ae then dev)
 * regardless of the directive's token order, so the key is deterministic. The
 * 0x1F (US) delimiter can never appear in a query string, so the suffix cannot
 * collide with a real arg value. Returns 0 when vary is UNSET/off. */
size_t
ngx_http_cache_turbo_vary_suffix(ngx_http_request_t *r, ngx_int_t vary,
    u_char *buf)
{
    ngx_str_t    cls;
    u_char      *w = buf;

    if (vary == NGX_CONF_UNSET || vary == 0) {
        return 0;
    }

    if (vary & NGX_HTTP_CACHE_TURBO_VARY_ENCODING) {
        cls = ngx_http_cache_turbo_ae_class(r);
        *w++ = 0x1F;
        w = ngx_cpymem(w, "ae=", 3);
        w = ngx_cpymem(w, cls.data, cls.len);
    }

    if (vary & NGX_HTTP_CACHE_TURBO_VARY_DEVICE) {
        cls = ngx_http_cache_turbo_device_class(r);
        *w++ = 0x1F;
        w = ngx_cpymem(w, "dev=", 4);
        w = ngx_cpymem(w, cls.data, cls.len);
    }

    return w - buf;
}


/* Set the variable to a pool-owned copy of len bytes of src, or the empty string
 * when len == 0. Shared "emit these bytes or nothing" tail for the argless output
 * paths (no args / strip_all / everything denied), where the suffix stands alone
 * with no leading '?'. */
ngx_int_t
ngx_http_cache_turbo_var_set(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, u_char *src, size_t len)
{
    u_char  *out;

    if (len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    out = ngx_pnalloc(r->pool, len);
    if (out == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(out, src, len);
    v->len = len;
    v->data = out;

    return NGX_OK;
}


/* --- auto-Vary (v11 other half) helpers --- */

/* Find a request header by (case-insensitive) name; returns its value or an
 * empty string when absent. Used for the raw-valued auto-Vary axes (Accept-
 * Language, Origin) that core does not expose as a typed field. */
static ngx_str_t
ngx_http_cache_turbo_req_header(ngx_http_request_t *r, const char *name,
    size_t nlen)
{
    ngx_list_part_t  *part = &r->headers_in.headers.part;
    ngx_table_elt_t  *h = part->elts;
    ngx_str_t         out = ngx_null_string;
    ngx_uint_t        i;

    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (h[i].hash == 0 || h[i].key.len != nlen) {
            continue;
        }
        if (ngx_strncasecmp(h[i].key.data, (u_char *) name, nlen) == 0) {
            return h[i].value;
        }
    }

    return out;
}


/* Accept-Language collapsed to the PRIMARY SUBTAG only, lowercased, so
 * `en-US,en;q=0.9` and `en-GB,en;q=0.8` fold to the same "en" class instead of
 * spawning a distinct variant per raw header string (i18n keyspace blowup).
 * Policy: take the first language-range of the header, cut at '-', drop any
 * ';q=' parameter, lowercase. Absent/empty/malformed header folds to the empty
 * class "" (NOT skipped — skipping the axis would collide with a genuinely
 * empty-but-present header). Result is capped at LANG_CLASS_MAX bytes; a
 * longer primary subtag is truncated, not rejected.
 *
 * Unlike ae_class/device_class this returns into a caller buffer rather than a
 * static string: the class is a truncated, lowercased slice of the raw header,
 * not a fixed enum member. len (out) is 0..LANG_CLASS_MAX.
 *
 * Unlike the COR-5 purge generation (folded ONLY when bumped, so an unpurged
 * base keeps its pre-upgrade variant key), this fold applies unconditionally:
 * every LANG-varying entry's variant key changes on upgrade (base keys are
 * unaffected — only the auto-Vary variant suffix moves). That one-time
 * keyspace turnover is the accepted, expected cost of collapsing the
 * raw-header keyspace to primary-subtag classes. */
#define NGX_HTTP_CACHE_TURBO_LANG_CLASS_MAX  8

static size_t
ngx_http_cache_turbo_lang_class(ngx_http_request_t *r, u_char *buf)
{
    ngx_str_t   v;
    u_char     *s, *last;
    size_t      len;

    v = ngx_http_cache_turbo_req_header(r, "Accept-Language",
                                        sizeof("Accept-Language") - 1);

    if (v.len == 0) {
        return 0;
    }

    s = v.data;
    last = v.data + v.len;

    /* first language-range = up to the first ',' */
    while (s < last && *s != ',') {
        s++;
    }
    last = s;
    s = v.data;

    /* primary subtag = up to the first '-' (also stops at ';q=' since ';'
     * terminates the range the same way '-' does for subtags) */
    while (s < last && *s != '-' && *s != ';') {
        s++;
    }

    len = (size_t) (s - v.data);
    if (len > NGX_HTTP_CACHE_TURBO_LANG_CLASS_MAX) {
        len = NGX_HTTP_CACHE_TURBO_LANG_CLASS_MAX;
    }

    ngx_strlow(buf, v.data, len);

    return len;
}


/* Derive the secondary VARIANT key from the base key material plus the request
 * values of the named (whitelisted) Vary axes. Axes are folded in a FIXED order
 * (ae, dev, lang, origin) regardless of the response Vary token order, so two
 * nodes / two requests with the same axis values compute the same key. Encoding,
 * device, and language (S7: primary-subtag class) are all bucketed to a class;
 * origin alone folds its raw value (CORS security boundary — see lang_class's
 * docstring for why LANG is classed but ORIGIN is not). The 0x1F (US) delimiter
 * can never appear in a URI or these header values, so the suffix cannot
 * collide with the base material. md5 fills the low 16 bytes; the high 16 are
 * zeroed first (the slot layout matches build_key, so a base and a variant
 * only ever differ by the folded bytes). */
ngx_int_t
ngx_http_cache_turbo_variant_hash(ngx_http_request_t *r, ngx_str_t *base,
    ngx_int_t bits, ngx_uint_t gen, u_char out[32])
{
    ngx_http_cache_turbo_digest_t  d;
    ngx_str_t                      cls;
    ngx_str_t                      v;
    static const u_char            us = 0x1F;

    ngx_http_cache_turbo_digest_init(&d);
    ngx_http_cache_turbo_digest_update(&d, base->data, base->len);

    /* PURGE generation (COR-5 / AUD-GEN1): folded UNCONDITIONALLY, including
     * gen == 0. The generation lives in one marker byte (marker_store truncates
     * to gen & 0xFF), so the 256th purge on a base wraps back to the SAME byte
     * value as a base that was never purged. Folding was previously skipped
     * for gen == 0 (treated as a "never purged" sentinel, kept for pre-COR-5
     * upgrade compatibility) -- that made the wrap land EXACTLY on the
     * untagged/never-purged variant keyspace, so a variant purged 256 times
     * could resurrect as a live HIT if its pre-purge/never-purged sibling was
     * still resident (long TTL / keep_stale forever / L1 LRU). Folding gen=0
     * too closes that specific collision at the cost of a one-time keyspace
     * turnover on upgrade (existing warm untagged entries stop matching and
     * are refetched once). A residual collision between generation N and
     * N+256 on the SAME base is NOT eliminated by this alone -- it is an
     * inherent limit of a one-byte counter, not the sentinel-vs-legacy
     * collision this fix closes; see AUD-GEN1 for the accepted trade-off and
     * the byte-widening follow-up it leaves open. */
    {
        u_char  gbuf[NGX_INT_T_LEN];
        size_t  glen;

        glen = (size_t) (ngx_sprintf(gbuf, "%ui", gen) - gbuf);
        ngx_http_cache_turbo_digest_update(&d, &us, 1);
        ngx_http_cache_turbo_digest_update(&d, "gen=", 4);
        ngx_http_cache_turbo_digest_update(&d, gbuf, glen);
    }

    if (bits & NGX_HTTP_CACHE_TURBO_VARY_ENCODING) {
        cls = ngx_http_cache_turbo_ae_class(r);
        ngx_http_cache_turbo_digest_update(&d, &us, 1);
        ngx_http_cache_turbo_digest_update(&d, "ae=", 3);
        ngx_http_cache_turbo_digest_update(&d, cls.data, cls.len);
    }
    if (bits & NGX_HTTP_CACHE_TURBO_VARY_DEVICE) {
        cls = ngx_http_cache_turbo_device_class(r);
        ngx_http_cache_turbo_digest_update(&d, &us, 1);
        ngx_http_cache_turbo_digest_update(&d, "dev=", 4);
        ngx_http_cache_turbo_digest_update(&d, cls.data, cls.len);
    }
    if (bits & NGX_HTTP_CACHE_TURBO_VARY_LANG) {
        u_char  lbuf[NGX_HTTP_CACHE_TURBO_LANG_CLASS_MAX];
        size_t  llen;

        llen = ngx_http_cache_turbo_lang_class(r, lbuf);
        ngx_http_cache_turbo_digest_update(&d, &us, 1);
        ngx_http_cache_turbo_digest_update(&d, "lang=", 5);
        ngx_http_cache_turbo_digest_update(&d, lbuf, llen);
    }
    if (bits & NGX_HTTP_CACHE_TURBO_VARY_ORIGIN) {
        v = ngx_http_cache_turbo_req_header(r, "Origin", sizeof("Origin") - 1);
        ngx_http_cache_turbo_digest_update(&d, &us, 1);
        ngx_http_cache_turbo_digest_update(&d, "org=", 4);
        ngx_http_cache_turbo_digest_update(&d, v.data, v.len);
    }

    return ngx_http_cache_turbo_digest_final(&d, out);
}


/* The dedicated L1 slot key for the vary marker of a base key. Distinct from the
 * object key (it folds a "varymark" tag) so the marker never collides with an
 * object slot or a cold-miss stub. */
ngx_int_t
ngx_http_cache_turbo_marker_hash(ngx_str_t *base, u_char out[32])
{
    ngx_http_cache_turbo_digest_t  d;
    static const u_char            us = 0x1F;

    ngx_http_cache_turbo_digest_init(&d);
    ngx_http_cache_turbo_digest_update(&d, base->data, base->len);
    ngx_http_cache_turbo_digest_update(&d, &us, 1);
    ngx_http_cache_turbo_digest_update(&d, "varymark", sizeof("varymark") - 1);
    return ngx_http_cache_turbo_digest_final(&d, out);
}


/* COR-5: build the per-base variant-index "tag name" into buf (>= 1 + 64). The
 * index reuses the L2 tag set machinery (SADD member + EXPIRE NX/GT, purge via
 * SMEMBERS); this name lands the set under <prefix>tag:<name>. A LEADING SPACE
 * frames it so no user `cache_turbo_tag` token can ever equal it: tag tokens are
 * split on whitespace, so a token can never contain a space. The body is the
 * 64-hex of a "varidx"-tagged digest of the base key material (deterministic
 * across nodes, like the variant/marker hashes). Returns NGX_OK with the byte
 * length in *len, or NGX_ERROR without publishing bytes/length. */
ngx_int_t
ngx_http_cache_turbo_variant_index_name(ngx_str_t *base, u_char *buf,
    size_t *len)
{
    ngx_http_cache_turbo_digest_t  d;
    u_char                         h[32];
    u_char                        *p;
    static const u_char            us = 0x1F;

    ngx_http_cache_turbo_digest_init(&d);
    ngx_http_cache_turbo_digest_update(&d, base->data, base->len);
    ngx_http_cache_turbo_digest_update(&d, &us, 1);
    ngx_http_cache_turbo_digest_update(&d, "varidx", sizeof("varidx") - 1);
    if (ngx_http_cache_turbo_digest_final(&d, h) != NGX_OK) {
        return NGX_ERROR;
    }

    buf[0] = ' ';
    p = ngx_hex_dump(buf + 1, h, 32);
    *len = (size_t) (p - buf);
    return NGX_OK;
}


/* Store/refresh a vary marker using its already-derived slot key. The L1 write
 * is mandatory and precedes the optional L2 write-through. The purge path uses
 * this entry point after preflighting every digest-derived key, so an EVP
 * failure cannot occur after it has deleted the base object. */
ngx_int_t
ngx_http_cache_turbo_marker_store_key(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_http_cache_turbo_zone_t *z, u_char marker_key[32], ngx_int_t bits,
    ngx_uint_t gen, time_t ttl, time_t retain_ttl)
{
    u_char                           blob[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE
                                          + 2];
    ngx_http_cache_turbo_blob_hdr_t  bh;

    ngx_memzero(&bh, sizeof(bh));
    /* A marker is a blob, so it must satisfy the blob contract: since AUD-HDR1
     * blob_validate() rejects a status outside 100..599, a memzero'd status 0
     * would make every marker unreadable. 200 is the only honest choice (the
     * marker records a successful classification); the body is still the 2-byte
     * [bits][gen] pair, which is what the readers actually consume. The shm
     * copy is node-local; a configured L2 receives the same validated marker
     * below. Any warm pre-AUD-HDR1 marker simply fails validation once and is
     * re-stored. */
    bh.status = NGX_HTTP_OK;
    bh.body_len = 2;
    bh.created = (int64_t) ngx_time();
    bh.fresh_ttl = (uint32_t) (ttl > 0 ? ttl : 0);
    /* P3-5 (codex-review perf finding): stale_ttl used to be re-derived from
     * `ttl` via stale_mult unconditionally, which was correct for a FRESH
     * classification (filters.c/purge.c: ttl IS the object's real fresh_ttl,
     * so stale_mult*ttl IS the object's real stale window) but wrong for the
     * L2-marker self-heal (access_l2_marker_consume()): there `ttl` is only
     * the marker's remaining FRESH life (rem_fresh, possibly floored to 1s),
     * and stale_mult*rem_fresh is nowhere close to the object's actual
     * remaining stale life (rem_stale) already known at that call site --
     * re-deriving from it silently truncated both the blob's own stale_ttl
     * field AND (see retain_ttl below) the L1/L2 slot's physical retention,
     * shortening a marker with hundreds of seconds left to a handful.
     * retain_ttl is now the caller's job explicitly: the two ORIGINAL
     * call sites (a fresh capture) pass stale_ttl(ttl, stale_mult), same
     * derivation as before; the self-heal call site passes the real
     * rem_stale it already computed, so the blob's own advertised
     * lifetime and the slot's physical retention finally agree. */
    bh.stale_ttl = (uint32_t) (retain_ttl > 0 ? retain_ttl : 0);
    ngx_http_cache_turbo_blob_hdr_write(blob, &bh);
    /* body = [axis bitmask][purge generation] (COR-5). The generation lets the
     * L1-only purge path orphan an old generation's variants by bumping it. */
    blob[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE]     = (u_char) (bits & 0xFF);
    blob[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 1] = (u_char) (gen & 0xFF);

    /* C3: not clcf->l1->store() -- this mandatory L1 copy and its `markers`
     * presence-counter bookkeeping are zone-shm-specific. _shm_store_marker()
     * folds both into the SAME lock hold (see its own comment in shm.c for why
     * that atomicity is required, not just tidy). The marker object itself is
     * not L1-only: a configured L2 receives the write-through below. */
    if (ngx_http_cache_turbo_shm_store_marker(z, marker_key,
            ngx_crc32_short(marker_key, 32), blob, sizeof(blob), ttl,
            retain_ttl) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* P3-5: write the marker through to L2 too, keyed by marker_hash (the
     * SAME key a marker-cold consult GETs -- see access_l2_marker_get()).
     * The L1 store above is node-local by design; this is what lets a
     * DIFFERENT node, cold for this
     * marker (fresh boot, LRU-evicted marker node), still learn "this base
     * URL has a classified variant" from L2 instead of falling straight
     * through to an unpopulated base-key L2 GET. Fire-and-forget async SET,
     * same as the L9 tag_add write-through a few lines below this call site
     * in filters.c -- never on the request's blocking path, and NULL-safe
     * (memcached's vtable has no atomic SADD/SMEMBERS for the variant
     * index, but `set` IS implemented on both backends, so this write-through
     * is not gated on backend->tag_add the way the variant index is). */
    if (clcf->backend && clcf->backend->set && r != NULL) {
        clcf->backend->set(r, clcf, marker_key, blob, sizeof(blob), ttl,
                           retain_ttl);
    }

    return NGX_OK;
}


/* Store/refresh a vary marker for a base key: a two-byte body carrying the
 * active-axis bitmask and purge generation, wrapped in the standard blob
 * header so a later read can validate the magic before trusting it. The shm
 * store copies the stack blob into node-local L1; marker_store_key() also
 * mirrors it to a configured L2 backend. */
ngx_int_t
ngx_http_cache_turbo_marker_store(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_http_cache_turbo_zone_t *z, ngx_str_t *base, ngx_int_t bits,
    ngx_uint_t gen, time_t ttl, time_t retain_ttl)
{
    u_char  marker_key[32];

    if (ngx_http_cache_turbo_marker_hash(base, marker_key) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_http_cache_turbo_marker_store_key(r, clcf, z, marker_key, bits,
                                                  gen, ttl, retain_ttl);
}


/* Lock-free half of the vary-marker probe: compute the marker key bytes for
 * the request's base key into ctx->vary_marker_key. marker_hash() only reads
 * ctx->cache_key and writes local/output stack memory, so this needs no zone
 * lock. Split out (S231-PERF-VARYLOCK) so the marker LOOKUP itself can be
 * folded into the caller's existing critical section instead of paying its
 * own separate ngx_shmtx_lock/unlock pair. */
ngx_int_t
ngx_http_cache_turbo_vary_prepare(ngx_http_cache_turbo_ctx_t *ctx)
{
    return ngx_http_cache_turbo_marker_hash(&ctx->cache_key,
                                             ctx->vary_marker_key);
}


/* Lock-HELD half of the vary-marker probe. Caller MUST already hold
 * z->shpool->mutex (S231-PERF-VARYLOCK: this used to take its own lock; it is
 * now folded into the main L1-lookup critical section in access_handler so a
 * request pays one shm-mutex acquisition for both lookups instead of two).
 *
 * Contract-diff vs. the old ngx_http_cache_turbo_vary_resolve() (which locked,
 * did exactly this read, and unlocked before returning):
 *  - Every early-return / no-op case is preserved verbatim: no marker, a NULL
 *    marker->data, too-short marker, an expired-with-no-grace marker, or a
 *    marker that fails blob_validate() (magic/version mismatch on a hash
 *    collision) all leave bits==0/gen==0 exactly as before, so key_hash/hash
 *    are left untouched by the caller and the request still falls through to
 *    a base-key miss -> origin. No case was dropped, widened or narrowed.
 *  - ctx->vary_gen is set unconditionally (bits==0 => gen==0), same as before.
 *  - On bits>0 it recomputes ctx->key_hash and *hash to the variant key, same as
 *    before, still called with the lock held (unlike the old code, which
 *    called variant_hash() AFTER unlocking — variant_hash() only reads
 *    ctx->cache_key/r and writes ctx->key_hash, none of which are shm-backed,
 *    so moving it inside the lock is a widening of the critical section, not
 *    a narrowing; nothing that used to run lock-free now depends on staying
 *    lock-free).
 *
 * Locking-window proof: `m` is a pointer INTO shm (the L1 vtable's lookup()
 * return), read here (m->data/m->len/m->stale_until, then a memcpy-free byte
 * read of m->data[...]) and never touched again after this function returns —
 * no pointer derived from `m` crosses the unlock at the end of the caller's
 * critical section, no refcount/acquire on `m` or its blob happens here (the
 * marker blob is never zero-copy-served, unlike a real object's ctn->data;
 * PERF-7's ngx_http_cache_turbo_blob_acquire() is never called on a marker
 * node in this function or its old counterpart). The only state that outlives
 * the lock is by-value: ctx->vary_gen (ngx_uint_t) and the bytes copied into
 * ctx->key_hash and *hash — plain stack/ctx memory, not shm. */
ngx_int_t
ngx_http_cache_turbo_vary_apply(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_ctx_t *ctx, uint32_t *hash)
{
    ngx_int_t                     bits = 0;
    ngx_uint_t                    gen = 0;
    time_t                        resolve_created = 0;
    ngx_http_cache_turbo_node_t  *m;

    m = clcf->l1->lookup(z, ctx->vary_marker_key,
                          ngx_crc32_short(ctx->vary_marker_key, 32));
    /* Accept a stale-but-serveable marker, not only a fresh one (codex
     * follow-up): the object variants it points at are themselves served stale
     * within their stale window, so gating the marker on fresh_until alone made
     * those stale variants unreachable (the request fell back to the base key
     * and re-fetched). The marker is refreshed on every variant store, so it
     * only goes stale alongside its objects. stale_until == 0 => forever. */
    if (m != NULL && m->data != NULL
        && m->len >= NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 1
        && (m->stale_until == 0 || ngx_time() < m->stale_until))
    {
        /* P1-6 (S231-PERF-VARYMAGIC): validate magic+version directly instead
         * of calling ngx_http_cache_turbo_blob_validate(), which additionally
         * walks the header-block TLV entries to decode/verify fields (status,
         * created, stale_ttl, nheaders, the header block itself) that this
         * caller never reads and immediately discards (pool == NULL, refs_out
         * == NULL). The marker blob has a fixed shape written only by
         * ngx_http_cache_turbo_marker_store(): headers_len == 0 (bh is
         * ngx_memzero'd and never sets it), so there is no TLV block to walk,
         * and the two body bytes this function reads sit at the FIXED offsets
         * NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE / +1, immediately after the
         * fixed-size (76-byte, CTB5) wire header -- independent of headers_len,
         * nheaders or anything the TLV walk computes. Reading them safely
         * requires exactly three things, all proven here: the magic matches
         * (blob_validate's own first check), the version matches (ditto), and
         * the buffer is at least HDR_WIRE + 1 byte (the `m->len >=
         * HDR_WIRE + 1` guard above, identical to what the outer `if` already
         * required before calling blob_validate) -- the bits-byte offset is
         * the same offset blob_validate would have proven safe via its
         * unconditional `len >= HDR_WIRE` check, since it lies exactly one
         * byte past the fixed header-sized prefix.
         *
         * A hash collision landing a real (non-marker) object blob under this
         * marker key still carries valid magic+version (same writer,
         * ngx_http_cache_turbo_blob_hdr_write()), so the extended
         * status/created/stale_ttl/TLV checks blob_validate performs never
         * actually distinguished a collision from a marker in practice --
         * they only ever rejected genuine corruption/truncation, which magic
         * + version + length continue to reject exactly as before. A
         * corrupt/truncated marker (bad magic, unknown version, or too short)
         * still leaves bits==0/gen==0, same fallthrough-to-base-key-miss
         * behaviour as the old blob_validate()-gated path. */
        if (ngx_http_cache_turbo_get_u32(m->data)
                == NGX_HTTP_CACHE_TURBO_BLOB_MAGIC
            && ngx_http_cache_turbo_get_u16(m->data + 4)
                   == NGX_HTTP_CACHE_TURBO_BLOB_VERSION)
        {
            bits = m->data[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE];
            /* COR-5: the purge generation lives in the 2nd body byte. Older
             * 1-byte markers (pre-COR-5, still warm in L1 after upgrade) lack
             * it => treat as gen 0. Same `len >= HDR_WIRE + 2` bounds check
             * as the old code before reading the 2nd body byte. */
            if (m->len >= NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 2) {
                gen = m->data[NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE + 1];
            }

            /* c-2: `created` (the marker's resolve time) already lives at
             * the fixed offset every blob_hdr_write() writes it to -- see
             * blob.c's blob_hdr_write()/put_u64(dst+24, created) and the
             * matching blob_validate() get_u64(blob+24). marker_store()
             * stamps it via ngx_time() on EVERY store, including the
             * self-heal writes below and in access_l2_marker_consume(), so
             * it doubles as "how long ago was this marker last resolved
             * from an authoritative source" with no wire-format change and
             * no second decode pass -- read directly like the magic/
             * version/bits/gen fields immediately above, not through the
             * full blob_validate() TLV walk (S231-PERF-VARYMAGIC's
             * reasoning applies identically here: this call already proved
             * the buffer is at least HDR_WIRE bytes, and offset 24..31 sits
             * inside that fixed-size prefix regardless of headers_len). */
            resolve_created = (time_t) ngx_http_cache_turbo_get_u64(
                                   m->data + 24);
        }
    }

    /* Carry the generation to the store path so the variant key + the refreshed
     * marker agree on it (store reuses ctx->vary_gen). */
    ctx->vary_gen = gen;

    if (bits > 0) {
        if (ngx_http_cache_turbo_variant_hash(r, &ctx->cache_key, bits, gen,
                                              ctx->key_hash) != NGX_OK)
        {
            return NGX_ERROR;
        }
        *hash = ngx_crc32_short(ctx->key_hash, 32);
        /* P3-5: an L1 hit is authoritative and strictly newer than any
         * earlier-pass L2 marker resolution still pending consumption (a
         * concurrent request could have written this very marker into L1
         * WHILE this request's own marker GET from a prior pass was still
         * in flight) -- clear vary_marker_l1_miss explicitly rather than
         * merely not setting it, since a stale 1 from an earlier pass of
         * THIS SAME request must not survive to gate anything after an L1
         * hit supersedes it. See access_l2_marker_consume(), which must
         * not let a landed-but-now-STALE L2 answer override what THIS pass
         * already resolved from L1. */
        ctx->vary_marker_l1_miss = 0;

        /* c-2: a warm L1 hit is authoritative for THIS request's answer
         * (key_hash/hash above are already the right variant to serve --
         * fail-open per the c-2 design, never blocked on the check below),
         * but it may be resolving a generation a PEER already orphaned via
         * PURGE. clcf->vary_marker_revalidate == 0 is the off switch
         * (today's behaviour: never re-check, matches the pre-c-2
         * contract exactly). Age is computed the same clock-skew-floored
         * way access_l2_marker_consume()/access_l2() already compute `age`
         * from a blob's `created`. This only ARMS the L2 revalidation
         * consult (access_l2_marker_get()/_consume()) for THIS pass; it
         * never issues a GET itself and never blocks -- see those
         * functions' field comments for how vary_marker_revalidate is
         * consumed without reintroducing a per-request round trip. */
        ctx->vary_marker_revalidate = 0;

        /* S231-NOCACHE-OUTAGE follow-up: never arm a revalidation while the
         * breaker is OPEN. access_l1()'s serve arms (serve_fresh/serve_stale)
         * are what run the breaker-fallback arm/SIE-arm phases and hand this
         * exact object to the pre-origin breaker gate as the STALE-BREAKER
         * snapshot -- diverting a request into the marker-revalidation
         * fall-through instead skips straight past that machinery on THIS
         * pass. That is fine when the origin is healthy (the object-GET
         * phase re-derives the correct status a moment later), but during a
         * real outage it means a routine, bounded generation recheck can
         * turn an ordinary cached HIT into extra latency riding the same
         * outage the breaker exists to shield against. A possibly-stale
         * cached variant must always beat that cost; revalidation is a
         * correctness improvement on the healthy path only. Peeking via
         * ngx_http_cache_turbo_brk_state() (a pure read of z->sh->
         * breaker_state) rather than the state-machine-driving
         * ngx_http_cache_turbo_shm_breaker_state() is deliberate: the latter
         * performs the due OPEN -> HALF_OPEN transition and promotes exactly
         * one caller per window to be the probe, and this is neither a
         * breaker consult nor a request that should ever become the probe --
         * it is speculative, pre-lookup work that must not perturb the
         * breaker state machine at all. */
        if (clcf->vary_marker_revalidate > 0 && !ctx->vary_marker_l2_done
            && !(ngx_http_cache_turbo_breaker_should_consult(clcf)
                 && ngx_http_cache_turbo_brk_state(ngx_http_cache_turbo_zone_sh(z)->breaker_state)
                        == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN))
        {
            time_t  age = ngx_time() - resolve_created;

            if (age < 0) {          /* clock skew between writers */
                age = 0;
            }
            if (age >= clcf->vary_marker_revalidate) {
                ctx->vary_marker_revalidate = 1;
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "cache_turbo: auto-Vary marker hit \"%V\" bits=0x%xi "
                       "-> variant key", &r->uri, bits);

    } else {
        /* P3-5: the L1 marker MISSED. key_hash is still the base key, and a
         * cold node (restart, LRU-evicted marker node) cannot tell from L1
         * alone whether a peer already classified + stored a variant for
         * this URL in L2 -- flag it so the L2 phase can consult the marker's
         * OWN L2-backed copy (marker_hash-keyed, written through by
         * marker_store) before falling back to a base-key L2 GET that a
         * varied URL's base slot never populates. */
        ctx->vary_marker_l1_miss = 1;
    }

    return NGX_OK;
}


/* True if the response already carries a non-identity Content-Encoding.
 *
 * SEC: a coding-specific body must never be cached under our encoding-blind
 * key. The filter-order fix (no ngx_module_order in `config`, so a lone
 * --add-dynamic-module registers LAST = TOP-most output filter; cache_turbo is
 * also kept the last --add-dynamic-module in the angie/nginx package build)
 * puts our body filter ABOVE the gzip/zstd/brotli filters, so a normal
 * compressed page reaches this filter as IDENTITY (no Content-Encoding yet)
 * and is captured uncompressed — the
 * compression filter then re-encodes it per client on both MISS and HIT. A
 * Content-Encoding still present here therefore means either the ORIGIN
 * pre-compressed the response (we hold no identity copy to re-encode) or we
 * were mis-ordered below a compressor. In both cases the stored bytes are
 * specific to one coding; replaying them to a client that negotiated a
 * different Accept-Encoding yields a browser "Content Encoding Error". Refuse
 * to capture rather than corrupt — this is the defense-in-depth guard that
 * holds even if the filter order is ever wrong. (Walks the typed field, which
 * upstream/proxy and the compression filters both populate.) */
ngx_uint_t
ngx_http_cache_turbo_response_encoded(ngx_http_request_t *r)
{
    ngx_table_elt_t  *ce = r->headers_out.content_encoding;

    if (ce == NULL || ce->hash == 0 || ce->value.len == 0) {
        return 0;
    }

    /* "identity" is the no-op coding — safe to cache as-is. */
    if (ce->value.len == sizeof("identity") - 1
        && ngx_strncasecmp(ce->value.data, (u_char *) "identity",
                           sizeof("identity") - 1) == 0)
    {
        return 0;
    }

    return 1;
}


/* P3-2: map a response's own Content-Encoding to the same 3-way enum
 * ngx_http_cache_turbo_ae_class() collapses the REQUEST's Accept-Encoding
 * into (zstd > br > gzip > identity, issues V6 priority). Used only when
 * response_encoded() has already proven the coding is non-identity, so the
 * IDENTITY return here means "some OTHER coding we don't special-case" (e.g.
 * `compress`, `deflate`) rather than "not encoded" -- callers that stamp
 * BLOBF_ORIGIN_ENCODED must treat that case as "cannot prove which class
 * accepts it" and refuse to key/serve it via this path at all. */
ngx_uint_t
ngx_http_cache_turbo_response_ae_class(ngx_http_request_t *r)
{
    ngx_table_elt_t  *ce = r->headers_out.content_encoding;

    if (ce == NULL || ce->hash == 0) {
        return NGX_HTTP_CACHE_TURBO_AE_CLASS_IDENTITY;
    }

    if (ce->value.len == 4
        && ngx_strncasecmp(ce->value.data, (u_char *) "zstd", 4) == 0)
    {
        return NGX_HTTP_CACHE_TURBO_AE_CLASS_ZSTD;
    }
    if (ce->value.len == 2
        && ngx_strncasecmp(ce->value.data, (u_char *) "br", 2) == 0)
    {
        return NGX_HTTP_CACHE_TURBO_AE_CLASS_BR;
    }
    if (ce->value.len == 4
        && ngx_strncasecmp(ce->value.data, (u_char *) "gzip", 4) == 0)
    {
        return NGX_HTTP_CACHE_TURBO_AE_CLASS_GZIP;
    }

    return NGX_HTTP_CACHE_TURBO_AE_CLASS_IDENTITY;
}


/* P3-2 SERVE-SIDE GUARD: does the REQUEST's Accept-Encoding actually accept
 * `class` (one of the NGX_HTTP_CACHE_TURBO_AE_CLASS_* enum values packed
 * into a BLOBF_ORIGIN_ENCODED blob's flags)? Reuses the same tokenised,
 * q-value-aware scan ngx_http_cache_turbo_ae_class() uses for the request-
 * side variant key, so "accepted" here means exactly what the variant key
 * itself would have classed the request as -- belt-and-braces on top of the
 * variant hash, not a second independent notion of acceptance (see
 * vary.c:196-201: the variant hash alone has already failed once).
 *
 * IDENTITY is always "accepted" (every client accepts identity, RFC 9110
 * 12.5.3) -- but a blob is only ever stamped ORIGIN_ENCODED for a NON-
 * identity coding (response_ae_class() returning IDENTITY at capture time
 * means "not one of zstd/br/gzip", which the capture gate below refuses to
 * key at all), so this arm is defensive completeness, not a live path. */
ngx_uint_t
ngx_http_cache_turbo_ae_class_accepted(ngx_http_request_t *r,
    ngx_uint_t class)
{
    ngx_table_elt_t  *ae = r->headers_in.accept_encoding;
    u_char           *p, *last, *end, *tok, *semi, *ce;
    size_t            clen;
    const char       *name;
    size_t            nlen;

    if (class == NGX_HTTP_CACHE_TURBO_AE_CLASS_IDENTITY) {
        return 1;
    }
    if (class == NGX_HTTP_CACHE_TURBO_AE_CLASS_ZSTD) {
        name = "zstd"; nlen = 4;
    } else if (class == NGX_HTTP_CACHE_TURBO_AE_CLASS_BR) {
        name = "br"; nlen = 2;
    } else if (class == NGX_HTTP_CACHE_TURBO_AE_CLASS_GZIP) {
        name = "gzip"; nlen = 4;
    } else {
        return 0;                              /* unknown class -> refuse */
    }

    if (ae == NULL || ae->value.len == 0) {
        return 0;                              /* absent AE accepts identity only */
    }

    p = ae->value.data;
    last = p + ae->value.len;

    while (p < last) {
        end = p;
        while (end < last && *end != ',') {
            end++;
        }

        semi = p;
        while (semi < end && *semi != ';') {
            semi++;
        }

        tok = p;
        while (tok < semi && (*tok == ' ' || *tok == '\t')) {
            tok++;
        }
        ce = semi;
        while (ce > tok && (ce[-1] == ' ' || ce[-1] == '\t')) {
            ce--;
        }
        clen = (size_t) (ce - tok);

        if (clen == nlen && ngx_strncasecmp(tok, (u_char *) name, nlen) == 0
            && ngx_http_cache_turbo_ae_q_ok(semi, end))
        {
            return 1;
        }

        p = (end < last) ? end + 1 : end;
    }

    return 0;
}


/* Phase 1 of ngx_http_cache_turbo_classify_vary(): is this header instance a
 * Vary header at all. Pure predicate, no state — kept as its own phase
 * because the caller's list-walk loop needs to `continue` on a non-Vary
 * instance before touching h[i].value, exactly as the inline check did. */
static ngx_int_t
ngx_http_cache_turbo_classify_vary_is_vary_header(const ngx_table_elt_t *h)
{
    return h->hash != 0
        && h->key.len == sizeof("Vary") - 1
        && ngx_strncasecmp(h->key.data, (u_char *) "Vary",
                            sizeof("Vary") - 1) == 0;
}


/* Phase 2 of ngx_http_cache_turbo_classify_vary(): locate the next
 * comma/whitespace-separated token starting at *pp (bounded by end), and
 * advance *pp past it so the caller's loop can call this again for the next
 * token. Returns the token in the tok/tl out-params. Returns 0 when the scan
 * hit `end` with nothing left, or produced a zero-length token (consecutive
 * separators) — the caller must `continue`/`break` its loop on that value
 * without reading *tokp or *tlp, exactly as the inline loop this replaces
 * did. Returns 1 when a non-empty token was produced. */
static ngx_int_t
ngx_http_cache_turbo_classify_vary_next_token(u_char **pp, u_char *end,
    u_char **tokp, size_t *tlp)
{
    u_char  *s, *tok;
    size_t   tl;

    s = *pp;

    while (s < end && (*s == ' ' || *s == '\t' || *s == ',')) {
        s++;
    }
    tok = s;
    while (s < end && *s != ' ' && *s != '\t' && *s != ',') {
        s++;
    }
    tl = (size_t) (s - tok);

    *pp = s;

    if (tl == 0) {
        return 0;
    }

    *tokp = tok;
    *tlp = tl;
    return 1;
}


/* Phase 3 of ngx_http_cache_turbo_classify_vary(): classify one already-
 * tokenised Vary axis name and fold it into *bits and *nocache. Arm order and
 * every veto trigger condition are unchanged from the inline if/else chain:
 * "*", Cookie, Authorization and any unrecognised axis each set the nocache
 * veto with the exact same test they used inline; the four whitelisted axes
 * each OR in their own bit and nothing else. This is the security-relevant
 * arm — a Vary axis we cannot key on must force nocache, because serving one
 * stored representation for every value of an un-split axis returns the
 * wrong representation to the wrong client (RFC 9110 12.5.5). Do not reorder
 * or collapse these arms. */
/* P0-1: unsafe_axis distinguishes the "genuinely unrecognised token" arm
 * (the final else) from the three NAMED vetoes ("*", Cookie, Authorization)
 * above it -- those three are attributable to a specific, already-documented
 * cause; an operator debugging a 0% hit ratio needs to know when it is
 * neither of those three, i.e. some other axis (Accept, X-Requested-With,
 * Sec-CH-* client hints, ...) the whitelist has no bit for (see PLAN P3-3). */
static void
ngx_http_cache_turbo_classify_vary_classify_token(u_char *tok, size_t tl,
    ngx_int_t *bits, ngx_uint_t *nocache, ngx_uint_t *unsafe_axis,
    ngx_uint_t response_encoded)
{
    if (tl == 1 && tok[0] == '*') {
        *nocache = 1;
    } else if (tl == sizeof("Cookie") - 1
        && ngx_strncasecmp(tok, (u_char *) "Cookie", tl) == 0) {
        *nocache = 1;
    } else if (tl == sizeof("Authorization") - 1
        && ngx_strncasecmp(tok, (u_char *) "Authorization", tl) == 0) {
        *nocache = 1;
    } else if (tl == sizeof("Accept-Encoding") - 1
        && ngx_strncasecmp(tok, (u_char *) "Accept-Encoding", tl) == 0) {
        /* P1-1: response_encoded() == 0 here means the stored representation
         * is provably identity (response_encoded()'s own capture-gate refusal
         * keeps any pre-encoded body out of the store), so the encoding axis
         * is inert for this response -- every Accept-Encoding value maps to
         * the same identity bytes. Skip the bit so the variant key collapses
         * instead of partitioning by a client header that cannot select a
         * different stored representation. A genuinely pre-encoded origin
         * response (response_encoded() == 1) still sets the bit and
         * partitions as before -- that copy IS coding-specific. */
        if (response_encoded) {
            *bits |= NGX_HTTP_CACHE_TURBO_VARY_ENCODING;
        }
    } else if (tl == sizeof("User-Agent") - 1
        && ngx_strncasecmp(tok, (u_char *) "User-Agent", tl) == 0) {
        *bits |= NGX_HTTP_CACHE_TURBO_VARY_DEVICE;
    } else if (tl == sizeof("Accept-Language") - 1
        && ngx_strncasecmp(tok, (u_char *) "Accept-Language", tl) == 0) {
        *bits |= NGX_HTTP_CACHE_TURBO_VARY_LANG;
    } else if (tl == sizeof("Origin") - 1
        && ngx_strncasecmp(tok, (u_char *) "Origin", tl) == 0) {
        *bits |= NGX_HTTP_CACHE_TURBO_VARY_ORIGIN;
    } else {
        /* A Vary axis we cannot key on. Caching anyway would serve one
         * stored representation for every value of this header - i.e.
         * the wrong representation (RFC 9110 12.5.5 / RFC 9111 4.1).
         * Refuse to cache, same as Cookie/Authorization/"*". */
        *nocache = 1;
        *unsafe_axis = 1;
    }
}


/* P3-3: is `tok`/`tl` (one already-tokenised Vary axis name) named by
 * `cache_turbo_vary_ignore`? Case-insensitive, same as every other header-name
 * compare in this file -- HTTP header names are case-insensitive and the
 * origin's casing on the Vary line is not under our control. clcf->vary_ignore
 * may be NULL/NGX_CONF_UNSET_PTR (nothing configured, the default) or an empty
 * array; both return 0 with no match attempted. */
static ngx_int_t
ngx_http_cache_turbo_vary_ignore_match(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *tok, size_t tl)
{
    ngx_str_t   *ignored;
    ngx_uint_t   i;

    if (clcf == NULL || clcf->vary_ignore == NULL
        || clcf->vary_ignore == NGX_CONF_UNSET_PTR)
    {
        return 0;
    }

    ignored = clcf->vary_ignore->elts;

    for (i = 0; i < clcf->vary_ignore->nelts; i++) {
        if (ignored[i].len == tl
            && ngx_strncasecmp(ignored[i].data, tok, tl) == 0)
        {
            return 1;
        }
    }

    return 0;
}


/* Classify the response Vary header into a safe-axis bitmask (what we may key
 * on) and a nocache veto. Only the whitelist (Accept-Encoding, User-Agent,
 * Accept-Language, Origin) contributes to the key. Anything else — Vary: *,
 * Cookie, Authorization, OR any header we cannot key on — forces the response
 * uncacheable, because serving one stored representation for every value of an
 * un-split Vary axis would return the wrong representation (RFC 9110 12.5.5).
 * Walks every Vary header instance and tokenises on comma/whitespace.
 *
 * P0-1: unsafe_axis_out (may be NULL) is set when the veto came from a
 * genuinely unrecognised axis token, as opposed to "*"/Cookie/Authorization
 * -- see classify_vary_classify_token().
 *
 * P3-3: a token named by `cache_turbo_vary_ignore` (clcf may be NULL, e.g.
 * from a caller with no location config in scope) is dropped BEFORE it ever
 * reaches classify_vary_classify_token() -- i.e. before the "*"/Cookie/
 * Authorization vetoes AND before the unknown-axis veto. An ignored token is
 * therefore treated exactly as if the origin had never listed it: it does not
 * contribute a bit to the variant key, it does not set nocache/unsafe_axis,
 * and it is NOT folded into the safe whitelist -- classify_token() never
 * sees it, so it cannot accidentally match one of the four whitelisted axis
 * names either. This is a deliberate cache-correctness override the operator
 * opts into per-header; see cache_turbo_vary_ignore's own doc comment. */
void
ngx_http_cache_turbo_classify_vary(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_int_t *bits_out,
    ngx_uint_t *nocache_out, ngx_uint_t *unsafe_axis_out)
{
    ngx_list_part_t  *part = &r->headers_out.headers.part;
    ngx_table_elt_t  *h = part->elts;
    ngx_int_t         bits = 0;
    ngx_uint_t        nocache = 0;
    ngx_uint_t        unsafe_axis = 0;
    ngx_uint_t        response_encoded;
    ngx_uint_t        i;

    /* P1-1: computed once per response, not per token -- same cost class as
     * the header-list walk this function already does, and the capture gate
     * re-checks response_encoded() itself later at no extra correctness
     * cost. */
    response_encoded = ngx_http_cache_turbo_response_encoded(r);

    for (i = 0; /* void */ ; i++) {
        u_char  *s, *e, *tok;
        size_t   tl;

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (!ngx_http_cache_turbo_classify_vary_is_vary_header(&h[i])) {
            continue;
        }

        s = h[i].value.data;
        e = s + h[i].value.len;

        while (s < e) {
            if (!ngx_http_cache_turbo_classify_vary_next_token(&s, e, &tok,
                                                                 &tl))
            {
                continue;
            }

            if (ngx_http_cache_turbo_vary_ignore_match(clcf, tok, tl)) {
                continue;
            }

            ngx_http_cache_turbo_classify_vary_classify_token(tok, tl,
                                                                &bits,
                                                                &nocache,
                                                                &unsafe_axis,
                                                                response_encoded);
        }
    }

    if (unsafe_axis_out != NULL) {
        *unsafe_axis_out = unsafe_axis;
    }

    /* A refused axis wins over any safe axis: don't cache a response that also
     * varies on Cookie, Authorization or "*", even if it also names a safe one. */
    if (nocache) {
        bits = 0;
    }

    *bits_out = bits;
    *nocache_out = nocache;
}

#pragma GCC visibility pop
