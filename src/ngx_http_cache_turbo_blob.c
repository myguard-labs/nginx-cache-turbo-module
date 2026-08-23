/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * SHA-256 content digest + L2 blob TLV deserializer, plus exit_process
 * (MAINT-SPLIT). Split out of ngx_http_cache_turbo_module.c: a leaf group
 * that calls nothing outside itself. ngx_http_cache_turbo_digest_t is
 * declared in ngx_http_cache_turbo_internal.h so module.c's digest() call
 * sites can still see the full type; ngx_http_cache_turbo_worker_md is
 * `extern` there too (this file's exit_process() frees it, same as before
 * the split) and ngx_http_cache_turbo_test_cookie_scans is declared there
 * for presets.c/module.c, unrelated to this file.
 * ngx_http_cache_turbo_exit_process() keeps its module.c forward
 * declaration (registered in ngx_http_cache_turbo_module's ngx_module_t),
 * now non-static so this TU can define it.
 * ngx_http_cache_turbo_digest() itself was already non-static (admin.c calls
 * it) and its prototype already lives in ngx_http_cache_turbo_module.h.
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

#if (NGX_SSL)
#include <ngx_event_openssl.h>
#endif



/* ------------------------------------------------------------------------- *
 * SEC-2: 256-bit content digest.
 *
 * The cache key hash is a 32-byte slot (the redis key is hex(slot[32]) = 64
 * chars). MD5 alone filled only the low 16 bytes (the high 16 stayed zero) =>
 * a 128-bit identity with no second-preimage/collision margin beyond MD5's
 * (broken) one. We now fill the whole slot with a real 256-bit digest:
 *
 *   - SHA-256 when built with SSL (libcrypto is linked — the shipped build uses
 *     --with-http_ssl_module). EVP one-shot/streaming API (not the deprecated
 *     SHA256_* low-level calls, which warn under -Werror on OpenSSL 3).
 *   - a double independent MD5 fold otherwise, so a no-SSL build still fills the
 *     full 32-byte slot with no OpenSSL dependency: low 16 = MD5(data),
 *     high 16 = MD5(domain-tag . data). Weaker than true SHA-256 but strictly
 *     wider than the old single-MD5-with-zero-pad.
 *
 * Either way the on-wire key is hex(slot[32]); the digest choice only changes
 * which bytes, so the keyspace turnover self-heals (old keys just miss). All
 * key-derivation sites (build_key, the variant/marker hashes, the admin
 * ?key= purge) MUST go through this one helper so they agree.
 * ------------------------------------------------------------------------- */

/* ngx_http_cache_turbo_digest_t is declared in ngx_http_cache_turbo_internal.h
 * (module.c needs the full type at its digest() call sites too). */

#if (NGX_SSL)
/* P6: one EVP_MD_CTX per worker, reused across every digest.
 *
 * nginx workers are single-threaded and a digest never spans an event-handler
 * return (init/update/final all run within one call), so there is no window in
 * which two digests are live at once and a single shared ctx is safe. Each
 * digest_init() does EVP_DigestInit_ex() on it, which resets the hash state —
 * so no residue carries between callers.
 *
 * Created lazily on first use rather than from an init_process hook, so a
 * digest issued before worker fork (config-time key derivation) still works.
 * Freed in exit_process; leaking it at shutdown would be harmless but shows up
 * under valgrind/ASan and the suite treats that as a failure.
 *
 * Non-static (declared `extern` in the internal header): module.c's
 * exit_process previously freed it directly; now exit_process itself lives
 * here too, but the symbol stays external in case another TU needs it.
 *
 * C0: the SAME lazy-not-init_process reasoning above governs
 * ngx_http_cache_turbo_worker_sha256 just below. EVP_sha256() returns a
 * legacy EVP_ORIG_GLOBAL handle, so on OpenSSL 3.x every EVP_DigestInit_ex()
 * call implicitly does a provider FETCH (property-string parse + hashtable
 * lookup) even though the algorithm never changes. Fetching the EVP_MD*
 * ONCE per worker and reusing it removes that repeated lookup from the hit
 * path. It is worker-persistent and lazily created for the identical
 * reason as the ctx: a digest can be issued before worker fork (config-time
 * key derivation), so an init_process hook would miss that call. Freed
 * alongside the ctx in exit_process. */
EVP_MD_CTX  *ngx_http_cache_turbo_worker_md;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
/* EVP_MD_fetch() does not exist before OpenSSL 3.0 and LibreSSL does not
 * implement the 3.0 provider API at all, so this whole cached-fetch path is
 * compiled out on both -- digest_init() below falls back to today's
 * EVP_sha256() call unconditionally in that case, byte-identical to the
 * pre-C0 code. */
EVP_MD  *ngx_http_cache_turbo_worker_sha256;
#endif
#endif

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
static ngx_uint_t  ngx_http_cache_turbo_test_digest_fail = 0;
#if (NGX_SSL) && OPENSSL_VERSION_NUMBER >= 0x30000000L \
    && !defined(LIBRESSL_VERSION_NUMBER)
/* C0 negative control: make digest_init() behave as though the worker's
 * cached EVP_MD_fetch() had returned NULL, without needing to fake OpenSSL
 * itself -- proves the fallback to EVP_sha256() takes over and still
 * produces the identical digest. */
static ngx_uint_t  ngx_http_cache_turbo_test_fetch_md_fail = 0;
#endif
#endif


/* Non-static: module.c's variant_hash()/varymark/varidx sites stream several
 * updates directly (a single-shot ngx_http_cache_turbo_digest() call would
 * not fit their multi-field digest), so init/update/final need external
 * linkage same as digest() itself. */
void
ngx_http_cache_turbo_digest_init(ngx_http_cache_turbo_digest_t *d)
{
#if (NGX_SSL)
    const EVP_MD  *md_type;

    if (ngx_http_cache_turbo_worker_md == NULL) {
        ngx_http_cache_turbo_worker_md = EVP_MD_CTX_new();
    }

    d->md = ngx_http_cache_turbo_worker_md;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
    {
        EVP_MD  *fetched;

        if (ngx_http_cache_turbo_worker_sha256 == NULL) {
            ngx_http_cache_turbo_worker_sha256 = EVP_MD_fetch(NULL, "SHA2-256",
                                                                NULL);
        }

        fetched = ngx_http_cache_turbo_worker_sha256;

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
        if (ngx_http_cache_turbo_test_fetch_md_fail) {
            fetched = NULL;
        }
#endif

        /* PERF: EVP_sha256() is evaluated ONLY on the fallback arm, never when
         * the worker-cached fetch is available. It returns a legacy
         * EVP_ORIG_GLOBAL handle, so OpenSSL 3 answers it with an implicit
         * EVP_MD_fetch -- a property query + provider hashtable lookup. That
         * is the very call PR #409 removed from EVP_DigestInit_ex's argument
         * (ossl_fnv1a_hash, 5.55% self-time); computing it here and then
         * discarding it on the common path paid the same cost again, 1-4x per
         * request (build_key + up to three vary sites).
         *
         * A NULL fetch (real OOM/provider-load failure, or the test knob
         * above) is a degraded-but-correct path, not an error: md_type falls
         * back to EVP_sha256() and the request is served exactly as before,
         * producing a byte-identical digest. */
        md_type = (fetched != NULL) ? (const EVP_MD *) fetched : EVP_sha256();
    }
#else
    /* No-guard fallback (pre-3.0 / LibreSSL): today's call, unchanged. */
    md_type = EVP_sha256();
#endif

    d->ok = (d->md != NULL
             && EVP_DigestInit_ex(d->md, md_type, NULL) == 1) ? 1 : 0;
#else
    static const u_char  tag[] = "ngx_http_cache_turbo\x1Fhi";

    ngx_md5_init(&d->lo);
    ngx_md5_init(&d->hi);
    ngx_md5_update(&d->hi, tag, sizeof(tag) - 1);
#endif
}


void
ngx_http_cache_turbo_digest_update(ngx_http_cache_turbo_digest_t *d,
    const void *data, size_t len)
{
#if (NGX_SSL)
    if (d->ok) {
        (void) EVP_DigestUpdate(d->md, data, len);
    }
#else
    ngx_md5_update(&d->lo, data, len);
    ngx_md5_update(&d->hi, data, len);
#endif
}


/* Finalise into the 32-byte slot. Returns NGX_OK on success, NGX_ERROR on failure. */
ngx_int_t
ngx_http_cache_turbo_digest_final(ngx_http_cache_turbo_digest_t *d,
    u_char out[32])
{
#if (NGX_SSL)
    unsigned int  n = 0;

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    if (ngx_http_cache_turbo_test_digest_fail) {
        d->md = NULL;
        return NGX_ERROR;
    }
#endif

    if (d->ok && EVP_DigestFinal_ex(d->md, out, &n) == 1 && n == 32) {
        /* P6: the ctx is worker-persistent — do NOT free it here. The next
         * digest_init() re-keys it via EVP_DigestInit_ex(); exit_process frees it. */
        d->md = NULL;
        return NGX_OK;
    } else {
        /* EVP_MD_CTX alloc/finalise failure (OOM) — fail closed: return error
         * so the caller skips caching rather than storing under an all-zero key. */
        d->md = NULL;
        return NGX_ERROR;
    }
#else
    ngx_md5_final(out, &d->lo);          /* low 16 */
    ngx_md5_final(out + 16, &d->hi);     /* high 16 */
    return NGX_OK;
#endif
}


/* One-shot convenience for a single contiguous input. Returns NGX_OK on success,
 * NGX_ERROR on failure. Non-static: called from admin.c too. */
ngx_int_t
ngx_http_cache_turbo_digest(const void *data, size_t len, u_char out[32])
{
    ngx_http_cache_turbo_digest_t  d;

    ngx_http_cache_turbo_digest_init(&d);
    ngx_http_cache_turbo_digest_update(&d, data, len);
    return ngx_http_cache_turbo_digest_final(&d, out);
}


/* P6: release the worker-persistent digest ctx (see digest_init). Non-static:
 * module.c's ngx_module_t struct registers it via a forward declaration. */
void
ngx_http_cache_turbo_exit_process(ngx_cycle_t *cycle)
{
    (void) cycle;

#if (NGX_SSL)
    if (ngx_http_cache_turbo_worker_md != NULL) {
        EVP_MD_CTX_free(ngx_http_cache_turbo_worker_md);
        ngx_http_cache_turbo_worker_md = NULL;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
    if (ngx_http_cache_turbo_worker_sha256 != NULL) {
        EVP_MD_free(ngx_http_cache_turbo_worker_sha256);
        ngx_http_cache_turbo_worker_sha256 = NULL;
    }
#endif
#endif
}


/* ------------------------------------------------------------------------- *
 * STAB-4: fixed little-endian, padding-free blob wire header (44 bytes, CTB4).
 * Written/read only through these helpers so the on-disk format is independent
 * of struct padding and host endianness. See the layout comment on
 * ngx_http_cache_turbo_blob_hdr_t in the header.
 * ------------------------------------------------------------------------- */

/* Non-static (declared in ngx_http_cache_turbo_internal.h): module.c's key-fold
 * and blob-write sites call these directly (put_u32) or transitively
 * (get_u16/32/64 via blob_validate/blob_hdr_write, both also called from
 * module.c). ngx_inline dropped along with `static` -- it only helps the
 * compiler fold a call within its own TU, which no longer applies here. */
void
ngx_http_cache_turbo_put_u16(u_char *p, uint16_t v)
{
    p[0] = (u_char) (v & 0xff);
    p[1] = (u_char) ((v >> 8) & 0xff);
}

void
ngx_http_cache_turbo_put_u32(u_char *p, uint32_t v)
{
    p[0] = (u_char) (v & 0xff);
    p[1] = (u_char) ((v >> 8) & 0xff);
    p[2] = (u_char) ((v >> 16) & 0xff);
    p[3] = (u_char) ((v >> 24) & 0xff);
}

void
ngx_http_cache_turbo_put_u64(u_char *p, uint64_t v)
{
    ngx_http_cache_turbo_put_u32(p, (uint32_t) (v & 0xffffffffULL));
    ngx_http_cache_turbo_put_u32(p + 4, (uint32_t) ((v >> 32) & 0xffffffffULL));
}

uint16_t
ngx_http_cache_turbo_get_u16(const u_char *p)
{
    return (uint16_t) (p[0] | ((uint16_t) p[1] << 8));
}

uint32_t
ngx_http_cache_turbo_get_u32(const u_char *p)
{
    return (uint32_t) p[0]
         | ((uint32_t) p[1] << 8)
         | ((uint32_t) p[2] << 16)
         | ((uint32_t) p[3] << 24);
}

uint64_t
ngx_http_cache_turbo_get_u64(const u_char *p)
{
    return (uint64_t) ngx_http_cache_turbo_get_u32(p)
         | ((uint64_t) ngx_http_cache_turbo_get_u32(p + 4) << 32);
}


/* Serialise the parsed header into NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE bytes.
 * Non-static: module.c's body_filter_blob_write() and variant paths call it. */
void
ngx_http_cache_turbo_blob_hdr_write(u_char *dst,
    const ngx_http_cache_turbo_blob_hdr_t *h)
{
    ngx_http_cache_turbo_put_u32(dst + 0,  NGX_HTTP_CACHE_TURBO_BLOB_MAGIC);
    ngx_http_cache_turbo_put_u16(dst + 4,  NGX_HTTP_CACHE_TURBO_BLOB_VERSION);
    ngx_http_cache_turbo_put_u16(dst + 6,  (uint16_t) h->flags);  /* BLOBF_* */
    ngx_http_cache_turbo_put_u32(dst + 8,  h->status);
    ngx_http_cache_turbo_put_u32(dst + 12, h->nheaders);
    ngx_http_cache_turbo_put_u32(dst + 16, h->headers_len);
    ngx_http_cache_turbo_put_u32(dst + 20, h->body_len);
    ngx_http_cache_turbo_put_u64(dst + 24, (uint64_t) h->created);
    ngx_http_cache_turbo_put_u32(dst + 32, h->fresh_ttl);
    ngx_http_cache_turbo_put_u32(dst + 36, h->stale_ttl);
    ngx_http_cache_turbo_put_u32(dst + 40, h->sie_ttl);   /* CTB4 (RFC-2 SIE) */
}


/*
 * P4-3: clear BLOBF_HDRS_VETTED on a blob that arrived from L2.
 *
 * The vetted bit asserts "ngx_http_cache_turbo_header_admissible() has
 * already run over every header pair in this blob". That is only true of a
 * blob this worker serialised itself. The store path hands the SAME buffer to
 * l1->store() and to backend->set() (filters.c), so the bit reaches Redis /
 * memcached and would come straight back set -- from a writer we do not
 * control. Honouring it off the wire turns one bit into a response-splitting
 * and Set-Cookie primitive (AUD-HDR1's exact threat model, AUD-TLS1's exact
 * attacker). Stripping it here demotes every L2 blob back to "must be
 * re-validated", i.e. to the behaviour that shipped before P4-3.
 *
 * Deliberately unconditional and total: it rewrites the u16 rather than
 * testing first, so there is no "was it set?" branch whose inverse could be
 * got wrong, and it is a no-op on a buffer too short to hold the 44-byte wire
 * header (such a blob is rejected by blob_validate() anyway, but the bounds
 * check must not depend on that ordering).
 *
 * The other flag bits are preserved untouched: BLOBF_BREAKER_ONLY and
 * BLOBF_ORIGIN_ENCODED are enforced at the serve chokepoint and are
 * RESTRICTIONS -- clearing them would fail OPEN. Only the vetted bit is a
 * permission, so only the vetted bit is dropped.
 */
void
ngx_http_cache_turbo_blob_clear_vetted(u_char *blob, size_t len)
{
    uint16_t  flags;

    if (blob == NULL || len < NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE) {
        return;
    }

    flags = (uint16_t) ngx_http_cache_turbo_get_u16(blob + 6);
    flags = (uint16_t) (flags & ~NGX_HTTP_CACHE_TURBO_BLOBF_HDRS_VETTED);
    ngx_http_cache_turbo_put_u16(blob + 6, flags);
}


/* Forward-declared so blob_validate() below can drive the same TLV iterator
 * it used to only be mirrored by; see the S231-PERF-HDRWALK comment on
 * ngx_http_cache_turbo_blob_next_header()'s definition further down. */
static ngx_int_t ngx_http_cache_turbo_blob_next_header(const u_char **pp,
    const u_char *end, const u_char **name, uint32_t *nlen,
    const u_char **val, uint32_t *vlen);


/*
 * Parse AND fully validate a stored blob in one place (STAB-4). On NGX_OK *out
 * holds the parsed header and (when non-NULL) *hdr_block / *body point at the
 * interior header block and body. Validates: minimum length, magic, version,
 * that the header block and body fit inside the buffer, AND that every TLV
 * header entry lies within the header block (a full walk). Doing the walk here
 * lets the L2-fill path reject a malformed blob BEFORE inserting it into L1 —
 * the old code stored first and only failed later in serve(), poisoning the L1
 * slot with a node that could never be served.
 *
 * S231-PERF-HDRWALK: when `pool` and `refs_out` are both non-NULL, the SAME
 * walk that validates each TLV entry's framing also records its four decoded
 * fields (name/nlen/val/vlen) into a pool-allocated array of *out->nheaders
 * ngx_http_cache_turbo_blob_href_t, written to *refs_out. A caller that only
 * needs framing validation (the L2-fill decide-and-store path, the fuzz
 * harness) passes pool == NULL and gets the original walk with no allocation.
 * ngx_http_cache_turbo_restore_response() passes r->pool and consumes the
 * array directly instead of re-walking the same bytes with
 * ngx_http_cache_turbo_blob_next_header() a second time — one walk, one set
 * of bounds checks, for every HIT. The array is bounded by nheaders, which is
 * itself bounded by headers_len <= len (each TLV entry costs >= 8 bytes), so
 * its size never exceeds len/8 pointers -- the same blob-size ceiling
 * (cache_turbo_max_object) that already bounds everything else here.
 *
 * Non-static: module.c calls it from the purge, access-L1-bounds,
 * serve, SIE-arm and body-filter sites.
 */
ngx_int_t
ngx_http_cache_turbo_blob_validate(const u_char *blob, size_t len,
    ngx_http_cache_turbo_blob_hdr_t *out, const u_char **hdr_block,
    const u_char **body, ngx_pool_t *pool,
    ngx_http_cache_turbo_blob_href_t **refs_out)
{
    const u_char                      *p, *end;
    uint32_t                           i;
    ngx_http_cache_turbo_blob_href_t  *refs = NULL;

    if (blob == NULL || len < NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE) {
        return NGX_ERROR;
    }
    if (ngx_http_cache_turbo_get_u32(blob) != NGX_HTTP_CACHE_TURBO_BLOB_MAGIC
        || ngx_http_cache_turbo_get_u16(blob + 4)
               != NGX_HTTP_CACHE_TURBO_BLOB_VERSION)
    {
        return NGX_ERROR;
    }

    out->magic       = NGX_HTTP_CACHE_TURBO_BLOB_MAGIC;
    out->version     = NGX_HTTP_CACHE_TURBO_BLOB_VERSION;
    out->status      = ngx_http_cache_turbo_get_u32(blob + 8);
    out->nheaders    = ngx_http_cache_turbo_get_u32(blob + 12);
    out->headers_len = ngx_http_cache_turbo_get_u32(blob + 16);
    out->body_len    = ngx_http_cache_turbo_get_u32(blob + 20);
    out->created     = (int64_t) ngx_http_cache_turbo_get_u64(blob + 24);
    out->fresh_ttl   = ngx_http_cache_turbo_get_u32(blob + 32);
    out->stale_ttl   = ngx_http_cache_turbo_get_u32(blob + 36);
    out->sie_ttl     = ngx_http_cache_turbo_get_u32(blob + 40);   /* CTB4 */
    /* S232-BYPASS-STALE: BLOBF_* bits from the formerly-reserved u16. No range
     * check -- unknown bits are ignored by every consumer (each tests its own
     * bit), and an old blob reads 0 = no bits set. Rejecting on an unknown bit
     * would make a future bit a keyspace-turnover event for no safety gain. */
    out->flags       = ngx_http_cache_turbo_get_u16(blob + 6);

    /*
     * AUD-HDR1: RANGE validation, not just framing. Everything below this point
     * is inherited by every consumer — restore_response() writes `status`
     * straight into r->headers_out.status, and the L2-fill path computes the
     * L1 lifetime from fresh_ttl/stale_ttl — so bounding the fields HERE is
     * what makes "the blob passed validation" mean something. Rejecting rather
     * than clamping is deliberate: these values are not degraded, they are
     * impossible, and a blob carrying them was not written by this module.
     *
     * NOTE on the TTLs: a bare "clamp to NGX_HTTP_CACHE_TURBO_TTL_MAX" would be
     * VACUOUS here — TTL_MAX is 0xFFFFFFFF and these are u32 wire fields, so it
     * can never fire. The invariant that does bite is stale_ttl >= fresh_ttl:
     * stale_ttl is the TOTAL serveable window (see the blob_hdr layout comment),
     * and every store-path shape satisfies it — stale_ttl() multiplies by
     * stale_mult >= 1, the stale-while-revalidate branch adds to ttl, and the
     * must-revalidate branch collapses it to exactly ttl. A forged blob claiming
     * a 136-year fresh_ttl under an ordinary stale window does not.
     */
    if (out->status < 100 || out->status > 599) {
        return NGX_ERROR;
    }
    if (out->stale_ttl < out->fresh_ttl) {
        return NGX_ERROR;
    }

    /*
     * AUD-BLOB-CREATED: bound `created` for the same reason status/stale_ttl
     * are bounded above — every downstream consumer computes
     * `now - created` (signed time_t subtraction) with no overflow check
     * before it, so an out-of-range `created` (e.g. INT64_MIN from a hostile
     * or corrupt L2 blob) is undefined behaviour before any later `age < 0`
     * clamp can run. See the NGX_HTTP_CACHE_TURBO_BLOB_CREATED_MIN comment in
     * the header for the range rationale. Reject, do not clamp: a `created`
     * outside this window was not written by this module's store path.
     */
    if (out->created < NGX_HTTP_CACHE_TURBO_BLOB_CREATED_MIN
        || out->created > (int64_t) ngx_time()
                               + (int64_t) NGX_HTTP_CACHE_TURBO_FOREVER_TTL)
    {
        return NGX_ERROR;
    }

    /* header block + body must fit (subtract on the remaining len — no overflow) */
    if (out->headers_len > len - NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE
        || out->body_len
               > len - NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE - out->headers_len)
    {
        return NGX_ERROR;
    }

    /* S231-PERF-HDRWALK: reject an nheaders that cannot possibly fit BEFORE
     * sizing the refs allocation below on it. Every TLV entry costs at least
     * 8 bytes (u32 name_len + u32 val_len, both possibly zero-length), so a
     * genuine blob never claims more than headers_len/8 entries; the walk
     * below would reject such a blob anyway (the first `end - p < 4/8` check
     * fails), but that rejection happens AFTER the allocation this bound now
     * guards. Without it a forged nheaders (e.g. 0xFFFFFFFF) on a tiny blob
     * would size a multi-GB pool allocation purely from an unvalidated wire
     * field -- not a size_t overflow (nheaders is u32, sizeof(href) is small,
     * the product fits in 64-bit size_t), but a self-inflicted allocation-size
     * DoS this validator exists to prevent. */
    if (out->nheaders > out->headers_len / 8) {
        return NGX_ERROR;
    }

    p   = blob + NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE;
    end = p + out->headers_len;

    /* Allocate the refs array (if requested) BEFORE the walk so each
     * iteration below can record straight into it -- one walk, not a
     * validate-pass followed by a separate fill-pass. nheaders is now bounded
     * by headers_len/8 above, and headers_len <= len <= cache_turbo_max_object
     * (1 MiB by default, configurable), so the allocation is bounded by the
     * same blob-size ceiling that already bounds everything else here. A zero
     * count allocates nothing (ngx_palloc(pool, 0) is never called).
     *
     * ngx_palloc(), NOT ngx_pnalloc(): ngx_http_cache_turbo_blob_href_t holds
     * two `const u_char *` members and needs NGX_ALIGNMENT (8-byte) placement.
     * ngx_pnalloc() is nginx's UNALIGNED allocator (used for strings/byte
     * buffers) -- pool->d.last is only byte-advanced by prior nlen/vlen-sized
     * requests in the same pool, so an odd offset there hands back a
     * misaligned `refs` pointer. Every `refs[i].name = ...` below then derefs
     * a pointer-typed struct member off an unaligned base, which is UB (caught
     * live by UBSan: "member access within misaligned address ... requires
     * 8 byte alignment" at this call site) and can fault on strict-alignment
     * platforms. ngx_palloc() rounds up to NGX_ALIGNMENT before handing back
     * memory, exactly like any other pointer-bearing struct allocated from
     * this pool. */
    if (pool != NULL && refs_out != NULL && out->nheaders > 0) {
        refs = ngx_palloc(pool,
                   out->nheaders * sizeof(ngx_http_cache_turbo_blob_href_t));
        if (refs == NULL) {
            return NGX_ERROR;
        }
    }

    for (i = 0; i < out->nheaders; i++) {
        uint32_t       nl, vl;
        const u_char  *name, *val;

        /* AUD-FUZZ1 / S231-PERF-HDRWALK: drive the SAME iterator restore used
         * to re-walk with, so blob_validate's bounds checks and the decoded
         * name/value pointers can never drift from each other -- one
         * implementation of "where does a TLV entry end", called from the
         * one place that walks the block. */
        if (ngx_http_cache_turbo_blob_next_header(&p, end, &name, &nl,
                                                   &val, &vl) != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (refs != NULL) {
            refs[i].name = name;
            refs[i].nlen = nl;
            refs[i].val  = val;
            refs[i].vlen = vl;
        }
    }

    if (hdr_block) { *hdr_block = blob + NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE; }
    if (body)      { *body = end; }
    if (pool != NULL && refs_out != NULL) { *refs_out = refs; }
    return NGX_OK;
}


/*
 * Decode ONE `u32 nlen | name | u32 vlen | value` TLV entry at *pp and advance
 * *pp past it. Returns NGX_OK with the four out-params pointing INTO the caller's
 * buffer, or NGX_DONE when the header block is exhausted or the next entry does
 * not fit (the walk stops, it never runs off `end`).
 *
 * AUD-FUZZ1 / S231-PERF-HDRWALK: this is the ONE walk. blob_validate() above
 * calls this exact function to both reject a malformed blob before it reaches
 * L1 AND (when asked) capture the decoded name/value pointers restore_response()
 * consumes directly — so validate and restore can no longer disagree about
 * where an entry ends, and the header region is walked once per HIT, not
 * twice. ci/fuzz/fuzz_blob.c drives this exact function too. The previous
 * open-coded copy in restore_response() was the only reader of the blob's TLV
 * framing that nothing tested; that copy is gone, this is the sole
 * implementation.
 */
static ngx_int_t
ngx_http_cache_turbo_blob_next_header(const u_char **pp, const u_char *end,
    const u_char **name, uint32_t *nlen, const u_char **val, uint32_t *vlen)
{
    const u_char  *p = *pp;
    uint32_t       nl, vl;

    if ((size_t) (end - p) < 8) { return NGX_DONE; }

    nl = ngx_http_cache_turbo_get_u32(p); p += 4;
    if ((size_t) (end - p) < nl) { return NGX_DONE; }
    *name = p; p += nl;

    if ((size_t) (end - p) < 4) { return NGX_DONE; }
    vl = ngx_http_cache_turbo_get_u32(p); p += 4;
    if ((size_t) (end - p) < vl) { return NGX_DONE; }
    *val = p; p += vl;

    *nlen = nl;
    *vlen = vl;
    *pp = p;
    return NGX_OK;
}

#pragma GCC visibility pop
