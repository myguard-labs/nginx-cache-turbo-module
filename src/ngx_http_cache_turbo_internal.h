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


#endif /* NGX_HTTP_CACHE_TURBO_INTERNAL_H_INCLUDED_ */
