/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Module-INTERNAL declarations (MAINT-C3). Everything here is used from
 * exactly one .c file -- it moved out of ngx_http_cache_turbo_module.h to
 * separate what genuinely must be shared across translation units (the
 * public header) from what is private to a single one. Behaviour-preserving
 * split only: no logic changed, no symbol renamed, no storage class changed
 * beyond what the single-file usage already implied.
 *
 * Included by every module .c file, right after ngx_http_cache_turbo_module.h,
 * so each TU still sees exactly the declarations it saw before the split --
 * only the header that carries them changed.
 */

#ifndef NGX_HTTP_CACHE_TURBO_INTERNAL_H_INCLUDED_
#define NGX_HTTP_CACHE_TURBO_INTERNAL_H_INCLUDED_


#include "ngx_http_cache_turbo_module.h"

#if (NGX_SSL)
#include <ngx_event_openssl.h>
#endif


/* ---- blob.c (SHA-256 digest + blob deserializer + exit_process; module.c
 * calls the digest/blob_validate helpers from many sites, so these are the
 * ONLY declarations here with external linkage that is not a whole-function
 * prototype) ---- */

typedef struct {
#if (NGX_SSL)
    EVP_MD_CTX  *md;
    ngx_int_t    ok;
#else
    ngx_md5_t    lo;
    ngx_md5_t    hi;
#endif
} ngx_http_cache_turbo_digest_t;

#if (NGX_SSL)
/* Worker-persistent digest ctx (see blob.c digest_init for the safety
 * argument). Defined and freed in blob.c's exit_process(); extern only so a
 * future second TU could inspect it, same visibility it had pre-split. */
extern EVP_MD_CTX  *ngx_http_cache_turbo_worker_md;
#endif

/* Registered in module.c's ngx_module_t (ngx_http_cache_turbo_module), which
 * keeps its own forward declaration of this prototype; defined in blob.c. */
void ngx_http_cache_turbo_exit_process(ngx_cycle_t *cycle);

/* module.c's variant_hash()/varymark/varidx sites stream digests directly
 * (not through the one-shot ngx_http_cache_turbo_digest(), whose prototype
 * already lives in ngx_http_cache_turbo_module.h). */
void ngx_http_cache_turbo_digest_init(ngx_http_cache_turbo_digest_t *d);
void ngx_http_cache_turbo_digest_update(ngx_http_cache_turbo_digest_t *d,
    const void *data, size_t len);
ngx_int_t ngx_http_cache_turbo_digest_final(ngx_http_cache_turbo_digest_t *d,
    u_char out[32]);

/* Fixed little-endian wire accessors (STAB-4). module.c's key-fold
 * (put_u32) and body-filter/variant (blob_hdr_write, get_u16/32/64 via
 * blob_validate) sites call these directly. */
void ngx_http_cache_turbo_put_u16(u_char *p, uint16_t v);
void ngx_http_cache_turbo_put_u32(u_char *p, uint32_t v);
void ngx_http_cache_turbo_put_u64(u_char *p, uint64_t v);
uint16_t ngx_http_cache_turbo_get_u16(const u_char *p);
uint32_t ngx_http_cache_turbo_get_u32(const u_char *p);
uint64_t ngx_http_cache_turbo_get_u64(const u_char *p);
/* ngx_http_cache_turbo_blob_hdr_write()'s prototype needs
 * ngx_http_cache_turbo_blob_hdr_t, which is defined further down in this
 * header (the "layout group" for blob_hdr_t / blob_href_t / BLOB_* below);
 * declared there instead, next to ngx_http_cache_turbo_blob_validate() which
 * has the same dependency. */

/* Test-only observable, defined and read entirely within module.c
 * (cookie_has() / cookie_scan_header sites); module.c already carries its own
 * `extern` immediately above its later use, this one is redundant but
 * harmless. TEST_FAULTS-gated so the symbol only exists in a test build. */
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
extern ngx_atomic_uint_t  ngx_http_cache_turbo_test_cookie_scans;
#endif


/* ---- presets.c (CMS auto-classify preset registry) ----
 *
 * ngx_http_cache_turbo_preset_t and its cookie-predicate struct are ALSO
 * defined verbatim in presets.c (inside its FUZZ-EXTRACT block), so the
 * generated fuzz .inc stays self-contained with no project-header include.
 * presets.c DOES include this header too (it needs the NGX_HTTP_CACHE_TURBO_
 * BACKEND_* bit constants that live in it), so it defines
 * NGX_HTTP_CACHE_TURBO_PRESETS_C first to suppress the typedef AND the
 * `extern ngx_http_cache_turbo_presets[]` declaration below -- a definition
 * needs neither a prior typedef (its own FUZZ-EXTRACT copy already supplied
 * one) nor a prior extern declaration in the same TU. Keep the two typedef
 * copies in sync if the layout ever changes. */

#ifndef NGX_HTTP_CACHE_TURBO_PRESETS_C

typedef struct ngx_http_cache_turbo_cookie_pred_s
               ngx_http_cache_turbo_cookie_pred_t;

#define NGX_HTTP_CACHE_TURBO_CVOP_NE        0   /* bypass when value != literal */
#define NGX_HTTP_CACHE_TURBO_CVOP_EQ        1   /* bypass when value == literal */
#define NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY  2   /* bypass when value is non-empty */

struct ngx_http_cache_turbo_cookie_pred_s {
    const char  *name_suffix;  /* cookie NAME must END with this (prefix-agnostic) */
    ngx_uint_t   op;           /* NGX_HTTP_CACHE_TURBO_CVOP_*                       */
    const char  *value;        /* literal compared against, NULL for NONEMPTY       */
};

typedef struct {
    ngx_uint_t           bit;
    const char *const   *cookies;  /* substrings in the request Cookie header */
    const char *const   *uris;     /* r->uri prefixes                         */
    const char *const   *args;     /* "name" (presence) or "name=value"       */
    const ngx_http_cache_turbo_cookie_pred_t  *cookie_preds;
    const char *const  *key_cookies;
} ngx_http_cache_turbo_preset_t;

/* Non-static: module.c iterates it (auto_skip / auto_key sites). */
extern const ngx_http_cache_turbo_preset_t  ngx_http_cache_turbo_presets[];

#endif /* !NGX_HTTP_CACHE_TURBO_PRESETS_C */


/* ---- shm.c (used only within ngx_http_cache_turbo_shm.c) ---- */

ngx_http_cache_turbo_node_t *
    ngx_http_cache_turbo_shm_lookup(ngx_http_cache_turbo_zone_t *z,
        u_char *key_hash, uint32_t hash);

ngx_int_t ngx_http_cache_turbo_shm_store(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, u_char *data, size_t len,
    time_t fresh_ttl, time_t stale_ttl);

/* Atomic decide-then-write store. See the L1 vtable `store_if` comment for
 * the return contract (NGX_OK / NGX_DECLINED / NGX_ERROR) and predicate
 * semantics. */
ngx_int_t ngx_http_cache_turbo_shm_store_if(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, u_char *data, size_t len,
    time_t fresh_ttl, time_t stale_ttl, ngx_uint_t predicate);

/* Purge a single entry by key hash. Returns 1 if an entry was removed, 0 if
 * not present. */
ngx_int_t ngx_http_cache_turbo_shm_purge_key(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash);

/* Purge every entry in the zone. Returns the number removed. */
ngx_uint_t ngx_http_cache_turbo_shm_purge_all(ngx_http_cache_turbo_zone_t *z);

/* Snapshot the zone's atomic stat counters into out (admin stats endpoint). */
void ngx_http_cache_turbo_shm_stats(ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_stats_t *out);

/* Cold-miss single-flight claim (v10). See the L1 vtable `claim` comment.
 * Returns NGX_HTTP_CACHE_TURBO_CLAIM_{WINNER,LOSER,FRESH}. */
ngx_int_t ngx_http_cache_turbo_shm_claim(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, time_t lock_ttl, uint64_t *owner);

/* min_uses miss counter (v15). See the L1 vtable `count_miss` comment. Returns
 * NGX_OK when the key has reached min_uses (store-eligible — proceed to the
 * normal cold path) or NGX_DECLINED when it is still below the threshold (go to
 * the origin without storing). A real entry (len > 0) or an in-flight stub
 * always returns NGX_OK without counting — refreshes are never re-gated. */
ngx_int_t ngx_http_cache_turbo_shm_count_miss(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, ngx_int_t min_uses);

/* S231-PERF-MISSLOCKS: merged count_miss()+claim() for the min_uses>1 &&
 * cache_turbo_lock-on cold path -- one zone-mutex hold, one rbtree descent,
 * instead of the two each standalone call used to take back-to-back on the
 * same key with no park between them. See the definition in
 * ngx_http_cache_turbo_shm.c for the exact contract (this is NOT a new
 * behaviour -- it is count_miss() immediately followed by claim() when it
 * returns NGX_OK, byte-identical to calling them separately).
 *
 * *count_miss_rc receives count_miss()'s own NGX_OK/NGX_DECLINED. When it is
 * NGX_DECLINED, claim() was NOT invoked (matches the caller's pre-existing
 * short-circuit) and the ngx_int_t return value is not meaningful -- callers
 * must check *count_miss_rc first, exactly as they already check
 * count_miss()'s return before ever calling claim(). When *count_miss_rc is
 * NGX_OK, the return value is claim()'s own CLAIM_WINNER/LOSER/FRESH and
 * *owner / *fresh_data / *fresh_len are populated exactly as claim() would
 * have. On CLAIM_FRESH, *fresh_data is an ALREADY-REFERENCED blob pointer --
 * the PERF-7 refcount (ngx_http_cache_turbo_blob_acquire()) was taken inside
 * the same critical section that read it, before this function's internal
 * unlock, precisely because that refcount is what keeps the pointer valid
 * once the lock is gone. The caller OWNS that reference on any non-NULL
 * *fresh_data and MUST release it (ngx_http_cache_turbo_blob_release()) on
 * every path that does not hand it to ngx_http_cache_turbo_serve(). See the
 * definition's comment for the full pointer-by-pointer locking-window
 * argument. l2_neg_check is intentionally NOT part of this merge; see the
 * definition's comment for why. */
ngx_int_t ngx_http_cache_turbo_shm_resolve_miss(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, ngx_int_t min_uses, time_t lock_ttl,
    uint64_t *owner, ngx_int_t *count_miss_rc,
    u_char **fresh_data, size_t *fresh_len);

/* L2 negative memo (L13). See the L1 vtable `l2_neg_check` / `l2_neg_set`
 * comments. check returns NGX_DECLINED to SKIP the L2 GET (a live memo), NGX_OK
 * to consult L2 as usual; set records a memo and is best-effort. */
ngx_int_t ngx_http_cache_turbo_shm_l2_neg_check(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash);
void ngx_http_cache_turbo_shm_l2_neg_set(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, time_t ttl);


/* ---- redis.c (used only within ngx_http_cache_turbo_redis.c) ---- */

/* Build the tag-set key "<prefix>tag:<name>" into buf (must hold
 * prefix.len + sizeof("tag:")-1 + name_len). Returns bytes written. */
size_t ngx_http_cache_turbo_redis_tagkey(ngx_str_t *prefix, u_char *name,
    size_t name_len, u_char *buf);

/* Async write-through: fire-and-forget SET <key> <blob> PX <ms>. Copies
 * everything it needs into its own pool, never blocks the worker, and survives
 * the request being finalised. Best-effort: failures are logged, not fatal.
 * retain_ttl is the caller-computed L2 key lifetime (see the `set` slot doc
 * comment on ngx_cache_turbo_backend_s) -- this function no longer derives
 * it from fresh_ttl. */
void ngx_http_cache_turbo_redis_set(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, u_char *key_hash,
    u_char *blob, size_t blob_len, time_t fresh_ttl, time_t retain_ttl);

/* Async fire-and-forget DEL <key>: drop an entry from L2 so a purge that
 * cleared L1 cannot be refilled from Redis (issue P6). Own pool, never blocks,
 * survives the request. No-op when L2 is disabled. */
void ngx_http_cache_turbo_redis_del(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *key_hash);

/* Fire-and-forget DEL of an arbitrary raw key (e.g. an emptied tag set). The
 * key bytes are copied immediately, so the caller's buffer need not outlive the
 * call. No-op when L2 is disabled. */
void ngx_http_cache_turbo_redis_del_raw(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *key, size_t key_len);

/* Tag index store: SADD "<prefix>tag:<name>" "<object L2 key>" + EXPIRE the tag
 * set to ttl seconds (refreshed each store). Async fire-and-forget. No-op when
 * L2 is disabled. */
void ngx_http_cache_turbo_redis_tag_add(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *key_hash, u_char *name, size_t name_len, time_t ttl);

/* L9: as tag_add, but indexes up to MAX_TAGS names for one object in a SINGLE
 * pipelined op (one pool, one connection, one round trip) instead of one op per
 * tag. names[] must already be deduped and MAX_TAGS-bound by the caller; empty
 * entries are skipped. Same fire-and-forget semantics as tag_add. */
void ngx_http_cache_turbo_redis_tag_add_many(
    ngx_http_cache_turbo_loc_conf_t *clcf, u_char *key_hash, ngx_str_t *names,
    ngx_uint_t nnames, time_t ttl);

/* Sync-park SMEMBERS "<prefix>tag:<name>": parks the request (count++) and,
 * when the array reply lands, invokes cb(r, data, members, n) then finalizes
 * with the rc cb returned. Returns:
 *   NGX_DONE  - parked; caller must return NGX_DONE
 *   NGX_ERROR - could not start (L2 disabled or connect failed); caller
 *               produces its own response. */
ngx_int_t ngx_http_cache_turbo_redis_smembers(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, u_char *name, size_t name_len,
    ngx_http_cache_turbo_redis_members_pt cb, void *data);

/* Cross-node single-flight (v4-2): async SET <lockkey> <owner> NX PX <ttl*1000>.
 * Parks the request (count++, NGX_AGAIN) until the reply lands, then sets
 * ctx->lock_done + ctx->lock_result (NGX_OK = acquired) and resumes the phase
 * engine. Returns NGX_AGAIN (parked) or NGX_DECLINED (L2 off / could not start;
 * caller proceeds as single-box). */
ngx_int_t ngx_http_cache_turbo_redis_lock(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx,
    time_t ttl);

/* Clear the whole L2 keyspace for this prefix (v4-2): parked SCAN MATCH
 * <prefix>* cursor loop, DEL each match, then cb(r, data, NULL, 0) emits the
 * response. Returns NGX_DONE (parked) or NGX_ERROR (L2 off / could not start). */
ngx_int_t ngx_http_cache_turbo_redis_scan_del(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_http_cache_turbo_redis_members_pt cb, void *data);



/* ---- MAINT-C3b: types/macros used from exactly one .c file ---- */

/* USE_STALE bitmask (module.c only) */
/*
 * cache_turbo_use_stale <off | error | timeout | http_403 | http_404 |
 *                         http_429 | http_500 | http_502 | http_503 |
 *                         http_504> ... Bitmask of which upstream response
 * classes are allowed to fall back to a stale cached copy, mirroring nginx's
 * own `proxy_cache_use_stale` vocabulary. Read on the request path by
 * ngx_http_cache_turbo_use_stale_triggers(), which gates the stale-if-error
 * rewrite in ngx_http_cache_turbo_header_filter() (S4.2).
 *
 * Bits are `ull` and the carrier is ngx_uint_t, same convention as
 * backend_presets above -- an unsuffixed literal at/above bit 31 would be
 * `unsigned int` and get truncated by promotion into a 64-bit mask.
 *
 * ⚠ `error` and `timeout` are NOT nginx-equivalent here, and the difference is
 * a known limitation rather than an oversight. In nginx these are
 * communication-failure classes inherited from proxy_next_upstream: `error`
 * means the connection failed/reset, `http_502` means the upstream really
 * answered 502. They are distinct conditions.
 *
 * This module cannot make that distinction. Its only observation point is
 * ngx_http_cache_turbo_header_filter, which sees r->headers_out.status and
 * nothing else -- there is no NGX_HTTP_UPSTREAM_FT_* state, no peer status, no
 * upstream failure provenance reachable from a header filter. By the time this
 * module runs, a refused connection and a genuine upstream 502 are the same
 * 502, and a timeout and a genuine 504 are the same 504.
 *
 * Consequence, which S4.2 must NOT paper over: with a status-only consumer,
 * `error` and `http_502` match the same set of responses, as do `timeout` and
 * `http_504`. An operator asking for `error` alone will also get stale serves
 * on a real upstream 502. The tokens exist for vocabulary compatibility with
 * proxy_cache_use_stale, not for behavioural parity.
 *
 * They carry their own bits so the parser records what the operator wrote and a
 * future consumer that DOES have provenance (e.g. one reading upstream state
 * rather than the final status) can honour the distinction without a config
 * break. Until such a consumer exists, treat ERROR as equivalent to HTTP_502
 * and TIMEOUT as equivalent to HTTP_504, and document the collapse rather than
 * claiming a fidelity this trigger site cannot deliver.
 *
 * `off` is exclusive: it is only accepted alone (any token alongside it is a
 * config error), and it means an EMPTY mask, not "keep default."
 *
 * DEFAULT (see ngx_http_cache_turbo_merge_loc_conf): HTTP_500 | HTTP_502 |
 * HTTP_503 | HTTP_504 | ANY_5XX. Today's only trigger site
 * (ngx_http_cache_turbo_header_filter) is unconditional on
 * `status >= NGX_HTTP_INTERNAL_SERVER_ERROR && status <= 599` -- i.e. EVERY
 * 5xx, not just the four named ones (506, 507, 508, 510, 511, ... are all
 * covered today). The four HTTP_5xx bits alone would silently narrow that on
 * the day S4.2 wires the read side, so ANY_5XX is a fifth bit carrying "every
 * other 5xx not already named by one of the four explicit bits" -- the merge
 * default sets all five bits, together reproducing "any 5xx" byte-for-byte.
 * ANY_5XX is deliberately NOT settable directly from the config vocabulary
 * (there is no `any_5xx` token): it exists solely so the default can be
 * expressed as a sum of named bits without the parser having to special-case
 * "no directive configured" as anything other than the ordinary UNSET/merge
 * path every other directive in this file already uses.
 */
#define NGX_HTTP_CACHE_TURBO_USE_STALE_ERROR      0x01ull /* own bit; folded onto 502 at the trigger */
#define NGX_HTTP_CACHE_TURBO_USE_STALE_TIMEOUT    0x02ull /* own bit; folded onto 504 at the trigger */
#define NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_403   0x04ull
#define NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_404   0x08ull
#define NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_429   0x10ull
#define NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_500   0x20ull
#define NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_502   0x40ull
#define NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_503   0x80ull
#define NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_504   0x100ull
/* "any other 5xx" -- see comment above. Kept well clear of the named bits and
 * of any future sentinel (backend_presets' NONE sentinel lives at bit 63; this
 * mask has no sentinel of its own, so there is no collision to avoid there,
 * but the gap still documents that this bit is not a real HTTP status). */
#define NGX_HTTP_CACHE_TURBO_USE_STALE_ANY_5XX    0x200ull

#define NGX_HTTP_CACHE_TURBO_USE_STALE_DEFAULT \
    (NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_500 \
     | NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_502 \
     | NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_503 \
     | NGX_HTTP_CACHE_TURBO_USE_STALE_HTTP_504 \
     | NGX_HTTP_CACHE_TURBO_USE_STALE_ANY_5XX)

/* backend preset bits WORDPRESS..OPENCART (module.c only) */
/*
 * Auto-classify CMS backend presets (distinct from the stale-window PRESET_*
 * above). A bitmask in loc_conf->backend_presets; each bit pulls in one row of
 * the preset registry (cookie/URI/arg dynamic-surface rules).
 *
 * EVERY preset is opt-in — you name the backends you actually run. There is no
 * `generic` / `auto` union, and deliberately so. It used to mean
 * WORDPRESS|WOOCOMMERCE|JOOMLA, and it was never a safe default:
 *
 *   - it never covered every backend, so `auto` on a Drupal or XenForo site
 *     silently enabled no rules for it at all;
 *   - WOOCOMMERCE inside it leaves /wp-admin/ cacheable unless stacked with
 *     WORDPRESS — a union whose members you must know how to combine is not a
 *     default;
 *   - JOOMLA inside it ships no cookie rule, so `auto` on a Joomla site LOOKED
 *     like it protected logged-in users and did not.
 *
 * Both spellings are now rejected at config parse (see cache_turbo_backend).
 *
 * The other reason no union is safe: most of these presets have generic-English
 * dynamic URIs — /login, /register, /contact, /misc (xenforo), /login, /signup,
 * /posts (discourse), /user, /admin, /node (drupal), /index.php (mediawiki) —
 * which an unrelated site may legitimately serve as perfectly cacheable pages.
 * Enabling one you do not run punches holes in your own cache.
 *
 * WIDTH: the bits are `ull` and the mask field is ngx_uint_t (64-bit on every
 * platform this module targets; nginx defines it as uintptr_t). The run was
 * 32-bit until it filled up at 31 presets + the NONE sentinel — a 32nd preset
 * would have aliased NONE and been silently invisible, because HAS_BACKEND()
 * masks NONE out. Keep every literal suffixed `ull`: an unsuffixed 0x80000000
 * is `unsigned int`, and the promotion in `mask & ~BIT` would then clear the
 * high half of a 64-bit mask on a plain-int operand. There is room for 63
 * presets; NONE is pinned to bit 63, the far end, so the preset run can grow
 * contiguously from bit 0 without ever colliding with it again.
 */
#define NGX_HTTP_CACHE_TURBO_BACKEND_WORDPRESS    0x0001ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_WOOCOMMERCE  0x0002ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_JOOMLA       0x0004ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_XENFORO      0x0008ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_DISCOURSE    0x0010ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_PHPBB        0x0020ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_DRUPAL       0x0040ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_MEDIAWIKI    0x0080ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_MAGENTO      0x0100ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_GHOST        0x0200ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_WAGTAIL      0x0400ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_KIRBY        0x0800ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_SHOPWARE6    0x1000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_TYPO3        0x2000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_INVISION     0x4000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_SMF          0x8000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_VANILLA      0x10000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_PUNBB        0x20000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_PHORUM       0x40000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_YABB         0x80000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_MYBB         0x100000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_VBULLETIN    0x200000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_TEXTPATTERN  0x400000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_BLUDIT       0x800000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_SPIP         0x1000000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_BUGZILLA     0x2000000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_MANTISBT     0x4000000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_PLONE        0x8000000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_UMBRACO      0x10000000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_DOTCLEAR     0x20000000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_WIKIJS       0x40000000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_REDMINE      0x80000000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_FLARUM       0x100000000ull
#define NGX_HTTP_CACHE_TURBO_BACKEND_OPENCART     0x200000000ull

/* ST_/SR_ serve outcome + reason enums (module.c only) */
/* Per-request serve outcome (ctx.status), surfaced by $cache_turbo_status.
 * Tokens mirror nginx $upstream_cache_status (HIT/MISS/EXPIRED/STALE/BYPASS).
 * MISS is 0 so a pcalloc'd ctx defaults to it; the serve/bypass/expired paths
 * override. EXPIRED = a cached entry was found past its serveable window and
 * refetched (NOT a cold miss, NOT only-if-cached-504 which stays MISS).
 * Keep ngx_http_cache_turbo_status_str() in the .c in sync with these. */
#define NGX_HTTP_CACHE_TURBO_ST_MISS     0
#define NGX_HTTP_CACHE_TURBO_ST_HIT      1
#define NGX_HTTP_CACHE_TURBO_ST_STALE    2
#define NGX_HTTP_CACHE_TURBO_ST_BYPASS   3
#define NGX_HTTP_CACHE_TURBO_ST_EXPIRED  4

/* S7.2: unfolded per-request serve reason, surfaced by
 * $cache_turbo_serve_reason. Unlike ctx.status/$cache_turbo_status (which
 * folds every non-HIT reason to STALE for $upstream_cache_status
 * compatibility and MUST keep doing so), this enum keeps the caller-supplied
 * reason distinct. NONE is 0 so a pcalloc'd ctx defaults to it (never
 * engaged / not yet decided -> "-" via not_found, same as status).
 * Keep ngx_http_cache_turbo_serve_reason_str() in the .c in sync. */
#define NGX_HTTP_CACHE_TURBO_SR_NONE            0
#define NGX_HTTP_CACHE_TURBO_SR_FRESH           1
#define NGX_HTTP_CACHE_TURBO_SR_STALE           2
#define NGX_HTTP_CACHE_TURBO_SR_STALE_IF_ERROR  3
#define NGX_HTTP_CACHE_TURBO_SR_STALE_BREAKER   4
#define NGX_HTTP_CACHE_TURBO_SR_BREAKER_503     5


/* VARY_* normalize-vary bits (module.c only) */


/*
 * Vary-aware normalize suffix (v3-4). Bitmask in loc_conf.normalize_vary chosen
 * by `cache_turbo_normalize_vary encoding device`. ENCODING appends an
 * Accept-Encoding class (br/gzip/identity); DEVICE appends a User-Agent device
 * class (mobile/desktop). Off by default so v3-1 keys are unchanged.
 */
#define NGX_HTTP_CACHE_TURBO_VARY_ENCODING  0x1
#define NGX_HTTP_CACHE_TURBO_VARY_DEVICE    0x2
/* auto-Vary (v11 other half): the same bits also drive the automatic variant
 * key derived from a response `Vary:` header (cache_turbo_auto_vary). LANG keys
 * on the Accept-Language PRIMARY SUBTAG CLASS (first language-range, cut at
 * '-', lowercased, capped at 8 bytes — e.g. `en-US,en;q=0.9` -> "en"; absent/
 * malformed folds to the empty class, it is not skipped); ORIGIN keys on the
 * raw Origin value (a CORS security boundary — folding it would let one
 * origin's response serve another's CORS headers, so it stays raw by design).
 * Only this safe whitelist is honoured — Vary: * / Cookie / Authorization make
 * the response uncacheable instead (cross-user poisoning/leak guard). */
#define NGX_HTTP_CACHE_TURBO_VARY_LANG      0x4
#define NGX_HTTP_CACHE_TURBO_VARY_ORIGIN    0x8

/* Worst-case suffix bytes: "\x1Fae=identity" (12) + "\x1Fdev=desktop" (12). The
 * delimiter is the raw 0x1F (US) byte, which a query string can never contain
 * (clients percent-encode control bytes), so the suffix cannot collide with a
 * real arg value. */
#define NGX_HTTP_CACHE_TURBO_VARY_SUFFIX_MAX  32

/* blobref_t + CT_BLOBREF (shm.c only, layout pair kept together) */
/* PERF-7: reference header prefixed to every slab-allocated response body so a
 * cache HIT can serve the blob DIRECTLY out of shm (zero-copy) instead of
 * memcpy'ing it into r->pool under the zone mutex. `data` (below) points at the
 * blob bytes that follow this header; the header is recovered with CT_BLOBREF().
 *
 * Lifetime: while a request serves a blob its output buffer points into the
 * slab, so the buffer must outlive eviction/refresh by another worker. `refs`
 * counts the in-flight zero-copy servers; `detached` is set when the owning node
 * has dropped this buffer (evict / refresh / purge). The slab is freed only when
 * refs == 0 AND detached — i.e. by whichever side is last (the evicting worker if
 * no serve is in flight, otherwise the last server's request-pool cleanup).
 * ALL fields are mutated only under shpool->mutex, so plain ints suffice (the
 * mutex is the barrier); no atomics. */
typedef struct {
    ngx_uint_t               refs;       /* in-flight zero-copy servers      */
    ngx_uint_t               detached;   /* owning node dropped this buffer  */
} ngx_http_cache_turbo_blobref_t;

#define CT_BLOBREF(data)                                                       \
    ((ngx_http_cache_turbo_blobref_t *)                                        \
        ((u_char *) (data) - sizeof(ngx_http_cache_turbo_blobref_t)))

/* NODE_ / SEG_ node-kind and LRU-segment enums (shm.c only) */
/* L1 node kind (L13-fix). What the node HOLDS -- the single authority, replacing
 * the old ad-hoc `len == 0 && data == NULL` shape sniffing. Every guard that used
 * to infer a node's role from its shape now reads `kind` instead.
 *
 * ⚠ ORTHOGONAL TO `refreshing`. A node's kind says what it holds; `refreshing`
 * says whether a single-flight regen is in the air for it. BOTH kinds can be
 * refreshing: an ENTRY refreshes while still serving its stale body (the v8
 * background-update dice, module.c), and a COUNTER refreshing is what the rest
 * of the code calls a STUB. So "is this a stub?" is exactly
 * `kind == COUNTER && refreshing`, never a shape test.
 *
 * History: stub / negative memo / min_uses counter were three meanings overloaded
 * onto one body-less shape, disambiguated by a different field at each site. Five
 * confirmed defects (Codex #1/#4/#5, CodeRabbit CR-A/CR-B on PR #77) were all
 * sites that picked the wrong disambiguator. See memory issues.md 2026-07-19. */
#define NGX_HTTP_CACHE_TURBO_NODE_ENTRY    0  /* holds a body (len > 0)        */
#define NGX_HTTP_CACHE_TURBO_NODE_COUNTER  1  /* no body: min_uses counter
                                               * and/or L13 negative memo, and
                                               * (when refreshing) the v10
                                               * cold-miss stub               */

/* S8 segmented-LRU segment ids. See the `seg` field below for why PROBATION
 * must stay 0. ci/tests/unit/extract_shm.sh pins both values. */
#define NGX_HTTP_CACHE_TURBO_SEG_PROBATION  0  /* on &sh->lru               */
#define NGX_HTTP_CACHE_TURBO_SEG_PROTECTED  1  /* on &sh->lru_protected     */

/* blob_hdr_t + BLOBF_BREAKER_ONLY + blob_href_t + BLOB_MAGIC/VERSION/HDR_WIRE/CREATED_MIN (module.c only, layout group kept together) */
/*
 * Serialised cache blob layout (one contiguous slab allocation):
 *
 *   [ 44-byte fixed wire header (see ngx_http_cache_turbo_blob_hdr_write) ]
 *   [ nheaders * { u32 name_len, name, u32 val_len, value } ]   (all u32 LE)
 *   [ body bytes ]
 *
 * The header block lets us restore Content-Type and any other response
 * headers on a cache hit, so cached responses are byte-identical to origin.
 *
 * created/fresh_ttl/stale_ttl/sie_ttl carry the object's ORIGINAL freshness so
 * an L2 hit can rebuild L1 with the remaining lifetime instead of resetting it
 * to the location default — without these, every L2 hit would re-promote a stale
 * object as fresh and it could live forever (and per-status/upstream TTLs would
 * be lost across the L2 round-trip). sie_ttl (RFC-2 stale-if-error, CTB4) is the
 * absolute serve-on-origin-error window from creation (fresh + stale-if-error N);
 * 0 = no serve-on-error past the normal stale window.
 *
 * STAB-4: the wire header is a FIXED little-endian, 44-byte, padding-free layout
 * (NOT this struct's native ABI) written/read only via the blob_hdr_write/
 * blob_validate helpers in module.c — so the on-disk format is independent of
 * compiler struct padding and host endianness. This struct is the in-memory
 * PARSED form; its field order/size is irrelevant to the wire. A single
 * ngx_http_cache_turbo_blob_validate() fully validates magic+version+all length
 * fields+the TLV header walk in one place, so a malformed L2 blob is rejected
 * BEFORE it is inserted into L1 (the old inline parse stored first, then serve()
 * failed = a poisoned L1 slot).
 *
 * Wire offsets (little-endian):
 *   0  u32 magic     ("CTB4")    16  u32 headers_len   32  u32 fresh_ttl
 *   4  u16 version   (= 4)       20  u32 body_len      36  u32 stale_ttl
 *   6  u16 flags     (BLOBF_*)   24  i64 created       40  u32 sie_ttl
 *   8  u32 status    12 u32 nheaders                   44  = header size
 *
 * S232-BYPASS-STALE: the u16 at offset 6 was reserved-and-always-0; it now
 * carries BLOBF_* bits. This is NOT a wire-layout change (the field was already
 * in the 44-byte header, already written as 0 and already skipped by every
 * reader), so magic/version are deliberately NOT bumped and no keyspace
 * turnover happens -- see the NOTE on BLOB_VERSION below for that rule. An old
 * CTB4 blob reads back flags = 0, which is exactly "no bits set".
 */
typedef struct {
    uint32_t                 magic;       /* 0x43544234 = "CTB4"            */
    uint32_t                 version;
    uint32_t                 nheaders;
    uint32_t                 headers_len; /* bytes of the header block      */
    uint32_t                 body_len;
    uint32_t                 status;
    int64_t                  created;     /* unix time (s) the blob was made */
    uint32_t                 fresh_ttl;   /* freshness seconds from created  */
    uint32_t                 stale_ttl;   /* total serveable window (>=fresh) */
    uint32_t                 sie_ttl;     /* abs serve-on-error window; 0=none */
    uint32_t                 flags;       /* BLOBF_* bits (wire u16 at off 6) */
} ngx_http_cache_turbo_blob_hdr_t;

/*
 * S232-BYPASS-STALE: this entry may ONLY be served by the pre-origin circuit
 * breaker gate, while the breaker is OPEN. It is permanently unreachable on the
 * normal hit path regardless of its age or TTLs -- the same "stored but only
 * the breaker can serve it" property an EXPIRED entry has (module.c, the L1
 * breaker-arm site), except it holds from the moment of the store rather than
 * being reached by ageing out.
 *
 * ⚠ This bit is the ENTIRE safety argument for cache_turbo_bypass_stale_uri.
 * The URIs an operator opts in are ones they had otherwise excluded from the
 * cache; storing them is only acceptable because nothing on the normal path can
 * reach the stored copy. Any code that serves a blob WITHOUT consulting this
 * bit reintroduces a cross-user disclosure on exactly those URIs. Grep for
 * BLOBF_BREAKER_ONLY before adding a new serve site.
 */
#define NGX_HTTP_CACHE_TURBO_BLOBF_BREAKER_ONLY  0x0001

/*
 * S231-PERF-HDRWALK: one parsed TLV header entry, as produced by the single
 * walk inside ngx_http_cache_turbo_blob_validate() and consumed directly by
 * ngx_http_cache_turbo_restore_response() -- no second bounds-checking pass
 * over the same bytes. name/val point INTO the caller's blob buffer (same
 * lifetime as the blob itself; no copy).
 */
typedef struct {
    const u_char             *name;
    uint32_t                  nlen;
    const u_char              *val;
    uint32_t                   vlen;
} ngx_http_cache_turbo_blob_href_t;

/* ---- blob.c: helpers whose signature needs the two structs just above ----
 * module.c calls all three: blob_hdr_write() from body-filter/variant sites,
 * blob_validate() from the purge, access-L1-bounds, serve, SIE-arm and
 * body-filter sites. */
void ngx_http_cache_turbo_blob_hdr_write(u_char *dst,
    const ngx_http_cache_turbo_blob_hdr_t *h);
ngx_int_t ngx_http_cache_turbo_blob_validate(const u_char *blob, size_t len,
    ngx_http_cache_turbo_blob_hdr_t *out, const u_char **hdr_block,
    const u_char **body, ngx_pool_t *pool,
    ngx_http_cache_turbo_blob_href_t **refs_out);


/* CTB4 (RFC-2 stale-if-error): fixed-endian versioned wire format. CTB4 adds the
 * sie_ttl u32 after stale_ttl (44-byte header). Old CTB1/CTB2/CTB3 blobs in L2
 * fail the magic/version check and are treated as a miss (cache self-heals), so
 * no migration is needed — the keyspace turns over once on upgrade.
 *
 * NOTE: the magic/version are bumped ONLY for an actual wire-LAYOUT change. A
 * purely semantic shift in already-laid-out bytes (e.g. the 2bcb914 switch from
 * storing a compressed body to an identity one) does NOT bump it — a reload
 * clears L1 shm and short TTLs age out any L2 copy, so a global keyspace
 * turnover would be unwarranted churn for a not-yet-in-production module. */
#define NGX_HTTP_CACHE_TURBO_BLOB_MAGIC    0x43544234
#define NGX_HTTP_CACHE_TURBO_BLOB_VERSION  4
/* Fixed wire size of the blob header (NOT sizeof the struct — that carries
 * native padding). All blob offsets derive from this constant. */
#define NGX_HTTP_CACHE_TURBO_BLOB_HDR_WIRE 44

/* Bounds on the blob's `created` field (AUD-BLOB-CREATED). It is stored as a
 * signed int64 wire field but is always written as `(int64_t) ngx_time()` at
 * store time (module.c) — a real store timestamp. Every consumer computes age
 * as `now - created` (time_t, i.e. plain signed subtraction) with NO overflow
 * check before it, e.g. `ngx_time() - (time_t) bh.created`; the `age < 0`
 * clamps downstream run only AFTER that subtraction has already happened.
 * A blob is not a trusted store artifact once it crosses L2 (Redis/memcached):
 * an attacker with L2 write access, or a corrupted/bit-flipped entry, can set
 * `created` to any int64, including INT64_MIN — `now - INT64_MIN` is signed
 * overflow, i.e. undefined behaviour, before any clamp gets a chance to run.
 * Reject rather than clamp, same as status/stale_ttl above: a `created` this
 * far from "a real store timestamp" was not written by this module. The floor
 * is 0 (this module's blob format did not exist before the Unix epoch); the
 * ceiling is FOREVER_TTL past "now" at validation time, generous enough to
 * absorb clock skew between nodes while still rejecting a blob claiming to
 * have been stored decades in the future. */
#define NGX_HTTP_CACHE_TURBO_BLOB_CREATED_MIN  ((int64_t) 0)

/* LOCK_POLL_MS (module.c only) */
/* Cold-miss wait-loop poll interval (ms): a loser re-checks L1/L2 this often
 * until the winner fills the entry or cache_turbo_lock_timeout elapses (v10). */
#define NGX_HTTP_CACHE_TURBO_LOCK_POLL_MS  100

/* memcached_ka_bucket_s/item_t/ka_t + MAX_BUCKETS + extern (memcached.c only) */
/* Memcached keepalive pool per-profile bucket (v14). Peer addr is the only
 * profile identity (no auth/TLS/db like redis). */
typedef struct ngx_http_cache_turbo_memcached_ka_bucket_s
    ngx_http_cache_turbo_memcached_ka_bucket_t;

typedef struct {
    ngx_queue_t                                     queue;
    ngx_connection_t                               *connection;
    ngx_http_cache_turbo_memcached_ka_bucket_t    *bucket;
} ngx_http_cache_turbo_memcached_ka_item_t;

struct ngx_http_cache_turbo_memcached_ka_bucket_s {
    ngx_uint_t   inited;
    ngx_uint_t   max;
    ngx_uint_t   count;
    ngx_msec_t   timeout;
    ngx_queue_t  cache;
    ngx_queue_t  free;
    ngx_http_cache_turbo_memcached_ka_item_t *items;
    socklen_t    socklen;
    ngx_sockaddr_t sockaddr;
};

#define NGX_HTTP_CACHE_TURBO_MEMCACHED_KA_MAX_BUCKETS  16

typedef struct {
    ngx_uint_t  nbuckets;
    ngx_http_cache_turbo_memcached_ka_bucket_t
                buckets[NGX_HTTP_CACHE_TURBO_MEMCACHED_KA_MAX_BUCKETS];
} ngx_http_cache_turbo_memcached_ka_t;

extern ngx_http_cache_turbo_memcached_ka_t ngx_http_cache_turbo_memcached_ka;


/* ---- vary.c (Vary/variant/Accept-Encoding classification group) ----
 *
 * module.c's access/header/body-filter phases (above this group's old
 * position in the file) call the auto-Vary prepare/apply pair and the
 * variant/marker digest helpers; ngx_http_cache_turbo_normalized_args_variable
 * (kept in module.c, in the $cache_turbo_normalized_args variable
 * registration block) calls the query-arg denylist and Vary-suffix helpers.
 * ngx_http_cache_turbo_vary_prepare loses the `ngx_inline` it had while
 * single-TU -- a cross-TU call cannot stay inline. */

void ngx_http_cache_turbo_vary_prepare(ngx_http_cache_turbo_ctx_t *ctx);
void ngx_http_cache_turbo_vary_apply(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_ctx_t *ctx, uint32_t *hash);
void ngx_http_cache_turbo_variant_hash(ngx_http_request_t *r,
    ngx_str_t *base, ngx_int_t bits, ngx_uint_t gen, u_char out[32]);
void ngx_http_cache_turbo_marker_hash(ngx_str_t *base, u_char out[32]);
void ngx_http_cache_turbo_marker_store(ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_http_cache_turbo_zone_t *z, ngx_str_t *base, ngx_int_t bits,
    ngx_uint_t gen, time_t ttl);
size_t ngx_http_cache_turbo_variant_index_name(ngx_str_t *base, u_char *buf);
void ngx_http_cache_turbo_classify_vary(ngx_http_request_t *r,
    ngx_int_t *bits_out, ngx_uint_t *nocache_out);
ngx_uint_t ngx_http_cache_turbo_response_encoded(ngx_http_request_t *r);

/* Called from ngx_http_cache_turbo_normalized_args_variable() in module.c. */
size_t ngx_http_cache_turbo_vary_suffix(ngx_http_request_t *r,
    ngx_int_t vary, u_char *buf);
ngx_int_t ngx_http_cache_turbo_var_set(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, u_char *src, size_t len);
ngx_int_t ngx_http_cache_turbo_name_denied(ngx_http_cache_turbo_loc_conf_t *clcf,
    u_char *name, size_t nlen);
ngx_int_t ngx_http_cache_turbo_tok_cmp(const void *one, const void *two);

#endif /* NGX_HTTP_CACHE_TURBO_INTERNAL_H_INCLUDED_ */
