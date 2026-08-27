/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * L1 shared-memory page cache: rbtree of cached objects keyed by the 32-byte
 * hash of the cache key, an LRU queue for eviction, and atomic stat counters.
 * Modelled on ngx_http_limit_req_module's slab+rbtree zone.
 *
 * Shared mutex: the zone mutex (z->shpool->mutex) uses nginx's ngx_shmtx,
 * which compiles to the atomic spin-then-futex variant when NGX_HAVE_ATOMIC_OPS
 * and NGX_HAVE_POSIX_SEM are both available (GCC atomics + POSIX semaphores).
 * This is the expected variant for contention analysis (P4-1).
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


/* --- P4-1a W-TinyLFU sketch constants. Declared here rather than beside the
 * helpers below because _shm_init_zone() sizes and allocates the sketch and
 * sits above them. ---
 *
 * NGX_HTTP_CACHE_TURBO_SKETCH_ROWS itself now lives in module.h (PERF-AUD2-11:
 * callers outside this TU need it to size the row-hash array they pass into
 * sketch_bump()/sketch_estimate()); the constant here is the same one, just
 * no longer redeclared -- four rows is still the standard count-min depth for
 * this use: the estimate is the min of four independent hashes, so a single
 * unlucky collision is masked by the other three. More rows buy little at
 * 4-bit precision and cost a linear multiple of the memory and of the
 * halving pass. */

/* 4-bit counters saturate here. Small on purpose: TinyLFU only needs to RANK
 * a candidate against a victim, not to count exactly, and 15 with periodic
 * halving distinguishes "never seen" from "hot" perfectly well. */
#define NGX_HTTP_CACHE_TURBO_SKETCH_MAX         15

/* Reset (halve every counter) after width * this many bumps. 10 is the classic
 * W-TinyLFU sample factor: the sample period scales with the sketch, so a
 * bigger zone ages more slowly in absolute terms and each key gets a
 * comparable number of chances to register before its history decays. */
#define NGX_HTTP_CACHE_TURBO_SKETCH_SAMPLE      10

/* Width bounds. The floor keeps a tiny zone's sketch from being so narrow
 * that every key collides (which would make every estimate equal and the
 * stage-2 test useless); the ceiling stops a very large zone from spending
 * more than the byte budget below on a frequency hint. Both are counters per
 * row, and both are powers of two so the row index is a mask, not a modulo. */
#define NGX_HTTP_CACHE_TURBO_SKETCH_MIN_WIDTH   1024
#define NGX_HTTP_CACHE_TURBO_SKETCH_MAX_WIDTH   (1 << 20)

/* PERF-AUD2-08: the full halving pass is split into this many stripes, so a
 * single crossing halves at most 1/STRIPES of the array instead of the whole
 * thing. See ngx_http_cache_turbo_sketch_halve() for the bound this
 * buys. 16 keeps the worst-case single-crossing pass at SKETCH_MAX_WIDTH's
 * 2 MB / 16 = 128 KB -- comfortably under a millisecond of memset-equivalent
 * work even on a slow core -- while still completing a full lap (and thus
 * incrementing sketch_gen) within 16 crossings, i.e. 16 * sketch_reset_at
 * bumps, which stays well inside "recent" for any zone busy enough for the
 * stall to matter. */
#define NGX_HTTP_CACHE_TURBO_SKETCH_HALVE_STRIPES  16


static void
ngx_http_cache_turbo_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t            **p;
    ngx_http_cache_turbo_node_t   *ctn, *ctnt;

    for ( ;; ) {
        if (node->key < temp->key) {
            p = &temp->left;

        } else if (node->key > temp->key) {
            p = &temp->right;

        } else {
            /* node->key == temp->key — disambiguate by full hash */
            ctn  = (ngx_http_cache_turbo_node_t *) node;
            ctnt = (ngx_http_cache_turbo_node_t *) temp;

            p = (ngx_memcmp(ctn->key, ctnt->key, 32) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


ngx_int_t
ngx_http_cache_turbo_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_cache_turbo_zone_t    *octx = data;
    ngx_http_cache_turbo_zone_t    *ctx;
    ngx_http_cache_turbo_stripe_t  *st;

    ctx = shm_zone->data;

    /* P4-2-s3b: publish the live stripe count BEFORE anything resolves a
     * stripe. ngx_http_cache_turbo_stripe_of() reads this field, and a zone
     * left at 0 would take its `nstripes <= 1` fail-safe branch rather than
     * the modulo -- correct, but only by accident. Set on the reload path too:
     * ctx is a FRESH cf->pool allocation on every cycle (only the shm contents
     * are inherited), so a reused zone arrives here with a zeroed array. */
    ctx->nstripes = NGX_HTTP_CACHE_TURBO_STRIPES;

    st = ngx_http_cache_turbo_zone_stripe(ctx);

    if (octx) {
        /* reused zone after reload: inherit the live shm */
        *st = *ngx_http_cache_turbo_zone_stripe(octx);
        /* ...but NOT the admission policy: it is the one field here that a
         * reload is expected to change. The fresh-zone tail below is the only
         * other writer, so without this a `cache_turbo_zone ... admission=`
         * flip was silently ignored until a full restart -- and silently, in
         * the worst way: the neighbouring protected_pct IS re-read per request
         * from clcf and does follow a reload, so an operator flipping both saw
         * one take effect and had no cue the other had not. */
        st->sh->admission = ctx->admission;
        return NGX_OK;
    }

    st->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        st->sh = st->shpool->data;
        st->sh->admission = ctx->admission;    /* same as above */
        return NGX_OK;
    }

    st->sh = ngx_slab_alloc(st->shpool,
                            sizeof(ngx_http_cache_turbo_shctx_t));
    if (st->sh == NULL) {
        return NGX_ERROR;
    }

    st->shpool->data = st->sh;

    ngx_rbtree_init(&st->sh->rbtree, &st->sh->sentinel,
                    ngx_http_cache_turbo_rbtree_insert_value);
    ngx_queue_init(&st->sh->lru);

    /* S8: the protected queue MUST be initialised even when scan resistance is
     * off. ngx_queue_empty() on a zeroed head reads h == h->prev as false
     * against NULL, so an uninitialised head would make evict_one() believe it
     * had a protected victim and walk a null sentinel. */
    ngx_queue_init(&st->sh->lru_protected);
    st->sh->n_protected = 0;
    st->sh->n_entries = 0;

    st->sh->hits = 0;
    st->sh->misses = 0;
    st->sh->stale_serves = 0;
    st->sh->refreshes = 0;
    st->sh->evictions = 0;
    st->sh->l2_hits = 0;
    st->sh->l2_misses = 0;
    st->sh->lock_waits = 0;
    st->sh->min_uses_skips = 0;
    st->sh->l2_neg_skips = 0;
    st->sh->bypasses = 0;
    st->sh->refuse_set_cookie = 0;
    st->sh->refuse_encoded = 0;
    st->sh->refuse_vary_unsafe = 0;
    st->sh->refuse_authorization = 0;
    st->sh->refuse_cache_control = 0;
    st->sh->refuse_require_header = 0;
    st->sh->refuse_partial = 0;
    st->sh->refuse_head = 0;

    /* Autotune state (v4-3): everything zeroed. autotune_next = 0 makes the first
     * recompute fire immediately; the snapshots being 0 means the first window is
     * "since worker start". autotuned_beta = 0 means "no verdict → use preset". */
    st->sh->cost_sum_ms = 0;
    st->sh->cost_count = 0;
    st->sh->autotuned_beta = 0;
    st->sh->autotuned_load = 0;   /* v4-4: 0 = baseline (no stale/lock widen) */
    st->sh->autotune_next = 0;
    st->sh->snap_hits = 0;
    st->sh->snap_misses = 0;
    st->sh->snap_refreshes = 0;
    st->sh->snap_cost_sum = 0;
    st->sh->snap_cost_count = 0;

    /* P6/O4.1 breaker: a fresh zone starts CLOSED, i.e. NOT tripped, so traffic
     * flows to the origin exactly as if the feature were off. Explicit rather
     * than relying on CLOSED == 0, because this is the fail-safe direction and
     * a reader should not have to know the constant's value to see that. */
    st->sh->breaker_state = NGX_HTTP_CACHE_TURBO_BREAKER_CLOSED;
    st->sh->breaker_fails = 0;
    st->sh->breaker_window_start = 0;
    st->sh->breaker_opened_at = 0;
    /* O4.4-h: the packed probe word. Generation 0 is NO_PROBE, so a zeroed word
     * reads "no lease held" whatever the stamp bits say -- the fail-safe
     * direction, and the reason the old `stamp != 0` guard is gone. */
    st->sh->breaker_probe = 0;

    /* O4.4-h: anchor for the probe word's RELATIVE stamp. Set once here; a
     * reload deliberately inherits the live shm (see the field block), so it
     * keeps the anchor an in-flight lease was stamped against. */
    st->sh->breaker_epoch = (ngx_atomic_t) ngx_time();
    st->sh->breaker_opens = 0;

    /* S7.1: production observability counters. */
    st->sh->sie_serves = 0;
    st->sh->breaker_serves = 0;
    st->sh->origin_failures = 0;

    /* COR-5(b)/L9: store-time index-drop counters. */
    st->sh->varidx_drops = 0;
    st->sh->varidx_reissues = 0;
    st->sh->tag_index_drops = 0;
    st->sh->tag_cap_drops = 0;

    /* S24: DISARMED, explicitly and unconditionally, and the explicitness is
     * not cosmetic. st->sh comes from ngx_slab_alloc(), which does NOT zero
     * (see the S231-EVICT-BLIND note at evict_one()), so an uninitialised
     * member here holds whatever the slab last had at that offset. In this
     * field's encoding 0 means ARMED-FOR-THE-NEXT-ALLOCATION, so omitting
     * this line would let a recycled byte pattern fail a genuine allocation
     * in any build carrying the injection branch. The field is unconditional
     * (see its declaration in module.h, which explains why) and so is this
     * initialisation -- one store on the once-per-zone carve path is not worth
     * a second #if, and keeping it unconditional means the shipping build
     * cannot drift into leaving the field undefined. */
    st->sh->fault_slab_countdown = NGX_HTTP_CACHE_TURBO_FAULT_DISARMED;

    /* P4-1a: allocate the W-TinyLFU frequency sketch.
     *
     * SIZING. The sketch is a FIXED overhead taken out of the same slab that
     * holds entries, so it is budgeted as a fraction of the zone rather than
     * from an entry count (there is no entry cap in this module -- the zone
     * fills until the slab is exhausted). One counter per row per ~4 KB of
     * zone, which for a 4-row sketch of 4-bit counters works out at
     *
     *     bytes = width * 4 rows / 2 counters-per-byte = width * 2
     *           = (zone / 4096) * 2 = zone / 2048
     *
     * i.e. 0.049% of the zone -- comfortably under the 1% target. A 64 MB
     * zone gets width 16384 and spends 32 KB; a 1 MB zone is below the
     * MIN_WIDTH floor and spends the floor's 2 KB (0.2%, still well under).
     * The width is rounded DOWN to a power of two so the row index is a mask.
     *
     * DEGRADES GRACEFULLY. On allocation failure `sketch` stays NULL and the
     * zone comes up normally: the estimate is unavailable, which stage 2 must
     * read as "no evidence", never as a reason to refuse an admission. A
     * frequency hint is not worth failing zone init over. */
    st->sh->sketch = NULL;
    st->sh->sketch_width = 0;
    st->sh->sketch_ops = 0;
    st->sh->sketch_reset_at = 0;
    st->sh->sketch_gen = 0;
    st->sh->sketch_cursor = 0;

    /* P4-1b: admission policy mirror + observability counters. The policy is
     * OFF unless the zone directive asked for it; ctx->admission was parsed
     * at config time (cache_turbo_zone ... admission=on). */
    st->sh->admission = ctx->admission;
    st->sh->sketch_bumps = 0;
    st->sh->admission_refused = 0;

    /* P4-2-s3a: live used-bytes gauge. Starts at 0 -- the sketch allocation
     * below is deliberately NOT charged: it is a fixed per-zone overhead
     * allocated once at init and never freed, not cached payload+metadata, and
     * including it would put a constant floor under the gauge that no eviction
     * or purge can ever return to baseline. */
    st->sh->used_bytes = 0;

    {
        ngx_uint_t  width, w, bytes;

        width = shm_zone->shm.size / 4096;

        if (width < NGX_HTTP_CACHE_TURBO_SKETCH_MIN_WIDTH) {
            width = NGX_HTTP_CACHE_TURBO_SKETCH_MIN_WIDTH;

        } else if (width > NGX_HTTP_CACHE_TURBO_SKETCH_MAX_WIDTH) {
            width = NGX_HTTP_CACHE_TURBO_SKETCH_MAX_WIDTH;
        }

        /* Round down to a power of two: the row index is `hash & (width - 1)`,
         * which is only a valid modulo for a power-of-two width. */
        for (w = NGX_HTTP_CACHE_TURBO_SKETCH_MIN_WIDTH;
             w <= width / 2;
             w <<= 1)
        {
            /* void */
        }
        width = w;

        bytes = width * NGX_HTTP_CACHE_TURBO_SKETCH_ROWS / 2;

        st->sh->sketch = ngx_slab_calloc(st->shpool, bytes);

        if (st->sh->sketch != NULL) {
            st->sh->sketch_width = width;
            st->sh->sketch_reset_at =
                width * NGX_HTTP_CACHE_TURBO_SKETCH_SAMPLE;
        }
    }

    st->shpool->log_nomem = 0;

    return NGX_OK;
}


/* C4: derive the rbtree ordering key from the first 8 bytes of the full
 * 32-byte key hash, instead of the caller's 32-bit crc32 short hash.
 * ngx_rbtree_key_t is ngx_uint_t -- 64 bits on every platform this module
 * ships for (nginx src/core/ngx_rbtree.h) -- so a bare crc32 wastes the top
 * half of every comparison. Two keys whose crc32 happens to collide
 * (1-in-2^32) now still separate on the primary rbtree compare almost every
 * time, so the ngx_memcmp() identity tiebreak in
 * ngx_http_cache_turbo_rbtree_insert_value() and shm_lookup() below is
 * reached far less often. It is NOT removed: 8 bytes still collide at a
 * real (if astronomically rarer) rate, and the tiebreak is the only thing
 * that actually proves two keys are the same key, not just 8 bytes of one.
 *
 * Returns ngx_uint_t, not ngx_rbtree_key_t -- the two are the same type
 * (see above) and this return type is what lets extract_shm.sh's function
 * slicer (ci/tests/unit/extract_shm.sh) recognise this as one of the
 * already-whitelisted return types instead of needing a new one.
 *
 * Explicit fixed-byte-order (big-endian) load, not a cast through a
 * (const ngx_uint_t *) -- a cast bakes host endianness into the tree's
 * iteration order, which would make node ordering (and anything that walks
 * the tree in key order) differ between a little- and a big-endian build of
 * byte-for-byte identical key material. */
static ngx_uint_t
ngx_http_cache_turbo_shm_key64(const u_char *key_hash)
{
    return ((ngx_uint_t) key_hash[0] << 56)
         | ((ngx_uint_t) key_hash[1] << 48)
         | ((ngx_uint_t) key_hash[2] << 40)
         | ((ngx_uint_t) key_hash[3] << 32)
         | ((ngx_uint_t) key_hash[4] << 24)
         | ((ngx_uint_t) key_hash[5] << 16)
         | ((ngx_uint_t) key_hash[6] << 8)
         |  (ngx_uint_t) key_hash[7];
}

/* Compile-time guard: the shift widths above assume ngx_rbtree_key_t is at
 * least 64 bits wide. It is on every platform this module ships for (see the
 * comment above), but if that ever stopped being true this must fail the
 * build, not silently shift UB into a truncated key. */
typedef char ngx_http_cache_turbo_key64_width_check
    [(sizeof(ngx_rbtree_key_t) >= 8) ? 1 : -1];


ngx_http_cache_turbo_node_t *
ngx_http_cache_turbo_shm_lookup(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash)
{
    ngx_int_t                     rc;
    ngx_rbtree_node_t            *node, *sentinel;
    ngx_http_cache_turbo_node_t  *ctn;
    ngx_rbtree_key_t              key;

    /* C4: descent now orders on the widened key derived from key_hash, not
     * on the caller's 32-bit crc32 short hash -- `hash` stays a parameter
     * (every one of this function's 16 call sites already has it in scope
     * for other purposes, e.g. the admission/sketch path) but is no longer
     * what decides tree position. */
    (void) hash;
    key = ngx_http_cache_turbo_shm_key64(key_hash);

    node = ngx_http_cache_turbo_zone_sh(z)->rbtree.root;
    sentinel = ngx_http_cache_turbo_zone_sh(z)->rbtree.sentinel;

    while (node != sentinel) {

        if (key < node->key) {
            node = node->left;
            continue;
        }

        if (key > node->key) {
            node = node->right;
            continue;
        }

        /* key == node->key */
        ctn = (ngx_http_cache_turbo_node_t *) node;

        rc = ngx_memcmp(key_hash, ctn->key, 32);

        if (rc == 0) {
            return ctn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static void ngx_http_cache_turbo_shm_free_locked(
    ngx_http_cache_turbo_zone_t *z, void *p, size_t size);
static void *ngx_http_cache_turbo_shm_alloc_evict(
    ngx_http_cache_turbo_zone_t *z, size_t size);


/* PERF-7: allocate a response blob with an ngx_http_cache_turbo_blobref_t header
 * prefixed, so a HIT can be served zero-copy out of shm under refcount. Returns
 * the BLOB pointer (== node->data; the header sits immediately before it), or
 * NULL on slab exhaustion. Caller holds the shpool mutex.
 *
 * C1: the header starts at refs == 1 / detached == 0 — that one reference IS
 * the owning node's, handed to the caller along with the pointer it is about to
 * store in node->data. It is released by blob_node_release(); see the protocol
 * note on ngx_http_cache_turbo_blobref_t. A caller that abandons the blob
 * without calling blob_node_release() leaks it, exactly as it would leak any
 * other slab allocation it dropped on the floor. */
static u_char *
ngx_http_cache_turbo_blob_alloc(ngx_http_cache_turbo_zone_t *z, size_t len)
{
    u_char                          *base;
    ngx_http_cache_turbo_blobref_t  *ref;

    base = ngx_http_cache_turbo_shm_alloc_evict(z,
               sizeof(ngx_http_cache_turbo_blobref_t) + len);
    if (base == NULL) {
        return NULL;
    }

    ref = (ngx_http_cache_turbo_blobref_t *) base;
    ref->refs = 1;                       /* C1: the owning node's reference */
    ref->detached = 0;
    /* P4-2-s3a: remember what alloc_evict() charged, so both free paths
     * (immediate here, deferred in blob_release) discharge exactly that. */
    ref->bytes = sizeof(ngx_http_cache_turbo_blobref_t) + len;

    return base + sizeof(ngx_http_cache_turbo_blobref_t);
}


/* PERF-7: the owning node drops its reference to a blob (evict / refresh / purge).
 * Caller holds the shpool mutex and `data` is non-NULL (node->data of a real
 * entry). Exactly once per blob: after this returns, the node no longer owns the
 * buffer and must not hand it out again.
 *
 * If no serve is in flight the node's was the last reference and the slab is
 * freed right here, under the mutex the caller already holds; otherwise the last
 * in-flight server frees it from its request-pool cleanup
 * (ngx_http_cache_turbo_blob_release).
 *
 * C1 ORDERING: `detached` is written BEFORE the decrement, while this thread
 * still holds the node's reference and the header is therefore guaranteed alive.
 * Once the decrement has run, a concurrent last server may already have freed
 * the header, so `ref` is not dereferenced again on either arm — `bytes` is
 * read up front, and the winner of the 1 -> 0 transition passes the address to
 * the slab without reading through it. */
static void
ngx_http_cache_turbo_blob_node_release(ngx_http_cache_turbo_zone_t *z,
    u_char *data)
{
    ngx_http_cache_turbo_blobref_t  *ref = CT_BLOBREF(data);
    size_t                           bytes = ref->bytes;

    ref->detached = 1;

    if (ngx_atomic_fetch_add(&ref->refs, -1) == 1) {
        ngx_http_cache_turbo_shm_free_locked(z, ref, bytes);
    }
}


/* PERF-7 exported helpers (see header).
 *
 * acquire() runs under the caller's ALREADY-HELD zone mutex and stays that way —
 * C1 does not widen it. It needs no failable compare-and-set (unlike the P4-2
 * lease CAS, which arbitrates between two workers racing for one slot) because
 * it never races the 1 -> 0 transition: it is reached only through a node the
 * caller resolved under that same mutex hold, and a node that still points at
 * this blob still holds its own reference, so refs >= 1 throughout. A DETACHED
 * blob is unreachable from every node by construction — blob_node_release() is
 * what detaches, and the caller drops the pointer in the same hold — so no
 * lookup can ever produce one to acquire. The count cannot resurrect from 0, and
 * an unconditional increment is therefore exact rather than optimistic. */
void
ngx_http_cache_turbo_blob_acquire(u_char *data)
{
    (void) ngx_atomic_fetch_add(&CT_BLOBREF(data)->refs, 1);
}


/* C1: release runs from a request-pool cleanup, on the request's own thread,
 * with NO lock held. The common case — a served blob whose node still owns it —
 * is now a single atomic decrement and a return, where it used to take the zone
 * mutex on every completed zero-copy HIT.
 *
 * The mutex is taken only on the terminal transition: refs 1 -> 0, which in the
 * biased scheme can only mean the owning node ALREADY released its reference
 * (i.e. the blob is detached) and this is the last server standing. That thread
 * is the sole owner of the header at that point — no other decrementer can
 * observe the same transition and no acquire can reach a detached blob — so
 * there is nothing left to re-check under the lock, and nothing the lock could
 * usefully arbitrate. It is held purely for the slab free list and the
 * used-bytes gauge that shm_free_locked() touches, never for the refcount. */
void
ngx_http_cache_turbo_blob_release(ngx_http_cache_turbo_zone_t *z, u_char *data)
{
    ngx_http_cache_turbo_blobref_t  *ref = CT_BLOBREF(data);
    /* Read while we still hold OUR reference, so both release paths obey one
     * flat rule: after your own decrement, never dereference `ref` again. */
    size_t                           bytes = ref->bytes;

    if (ngx_atomic_fetch_add(&ref->refs, -1) != 1) {
        return;                  /* another owner remains: nothing to free */
    }

    ngx_shmtx_lock(ngx_http_cache_turbo_zone_mutex(z));
    ngx_http_cache_turbo_shm_free_locked(z, ref, bytes);
    ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));
}


/* --- P4-1a W-TinyLFU frequency sketch --------------------------------------
 *
 * STAGE 1 OF 2: estimation machinery only. Nothing in this stage READS an
 * estimate to decide anything, so admission and eviction are byte-for-byte
 * unchanged; the sketch is pure bookkeeping until stage 2 adds the admission
 * test. See the field block in module.h for the layout and the reload note.
 *
 * Caller holds the shpool mutex for every function here. The counters are
 * plain memory, not atomics, precisely because of that.
 */

/* Per-row hash. The caller passes ONE key hash; each row needs its own
 * position or the four rows would collide identically and the min would carry
 * no more information than a single row. Mixing the row index into the hash
 * with a 32-bit finalizer (the MurmurHash3 fmix32 avalanche) is the cheap
 * standard way to get four independent-enough positions out of one hash. */
static ngx_inline uint32_t
ngx_http_cache_turbo_sketch_row_hash(uint32_t hash, ngx_uint_t row)
{
    uint32_t  h = hash ^ (uint32_t) (0x9e3779b9u * (row + 1));

    h ^= h >> 16;
    h *= 0x85ebca6bu;
    h ^= h >> 13;
    h *= 0xc2b2ae35u;
    h ^= h >> 16;

    return h;
}


/* PERF-AUD2-11: compute all NGX_HTTP_CACHE_TURBO_SKETCH_ROWS row-hashes for
 * one `hash` in a single pass. sketch_bump()/sketch_estimate() each used to
 * call ngx_http_cache_turbo_sketch_row_hash() fresh, per row, INSIDE the
 * zone-mutex critical section they run in -- 4 rounds of fmix32 (3 multiplies
 * + 3 shifts per round) that depend only on `hash` and `row`, both known to
 * the caller before this call. Computing the array once and threading it
 * through removes the recompute from the two hot per-row loops below; the
 * fmix32 avalanche work itself is unavoidable (it is what makes the four
 * rows independent-enough), only the redundant re-derivation is removed. */
static ngx_inline void
ngx_http_cache_turbo_sketch_rows(uint32_t hash,
    uint32_t rows[NGX_HTTP_CACHE_TURBO_SKETCH_ROWS])
{
    ngx_uint_t  row;

    for (row = 0; row < NGX_HTTP_CACHE_TURBO_SKETCH_ROWS; row++) {
        rows[row] = ngx_http_cache_turbo_sketch_row_hash(hash, row);
    }
}


/* Read one 4-bit counter. `idx` is a counter index across the whole flat
 * array (row offset already applied), NOT a byte index: two counters share a
 * byte, the even index in the LOW nibble and the odd index in the HIGH one. */
static ngx_inline ngx_uint_t
ngx_http_cache_turbo_sketch_get(u_char *sketch, ngx_uint_t idx)
{
    u_char  b = sketch[idx >> 1];

    return (idx & 1) ? (ngx_uint_t) (b >> 4) : (ngx_uint_t) (b & 0x0f);
}


/* Saturating 4-bit increment of one counter. Returns nothing: a caller that
 * wants the value reads it back. */
static ngx_inline void
ngx_http_cache_turbo_sketch_inc(u_char *sketch, ngx_uint_t idx)
{
    ngx_uint_t  byte = idx >> 1;

    if (idx & 1) {
        if ((sketch[byte] >> 4) < NGX_HTTP_CACHE_TURBO_SKETCH_MAX) {
            sketch[byte] = (u_char) (sketch[byte] + 0x10);
        }

    } else {
        if ((sketch[byte] & 0x0f) < NGX_HTTP_CACHE_TURBO_SKETCH_MAX) {
            sketch[byte] = (u_char) (sketch[byte] + 0x01);
        }
    }
}


/* PERF-AUD2-08: halve ONE STRIPE of the array (the TinyLFU aging step made
 * incremental), starting at sketch_cursor, then advance the cursor. Only when
 * the cursor WRAPS -- this stripe reached or passed the end of the array --
 * has a full lap completed, and only then does sketch_gen advance. A gen
 * bump on every stripe would tell a reader "history just decayed" up to
 * HALVE_STRIPES times more often than it actually did; readers (admin/metrics
 * only -- see the module.h field comment) are documented as counting full
 * laps, not stripes.
 *
 * BOUNDED BY CONSTRUCTION: exactly
 * ceil(sketch_width * ROWS / 2 / HALVE_STRIPES) byte writes per call, with
 * sketch_width capped at SKETCH_MAX_WIDTH, so the worst case per call is a
 * fixed 2 MB / HALVE_STRIPES pass and cannot grow with traffic or entry
 * count -- same bound class as the original whole-array pass, just paid in
 * HALVE_STRIPES smaller instalments instead of one. Both nibbles of a byte
 * halve in one masked shift -- shifting the byte would bleed the high
 * counter's low bit into the low counter's top bit.
 *
 * The last stripe of a lap absorbs any remainder (bytes not evenly divisible
 * by HALVE_STRIPES): it runs to the true end of the array rather than a
 * fixed stripe width, so no byte is ever skipped and no lap runs long. */
static void
ngx_http_cache_turbo_sketch_halve(ngx_http_cache_turbo_zone_t *z)
{
    ngx_uint_t  i, bytes, stripe, start, end;
    u_char     *sketch = ngx_http_cache_turbo_zone_sh(z)->sketch;

    bytes  = ngx_http_cache_turbo_zone_sh(z)->sketch_width
             * NGX_HTTP_CACHE_TURBO_SKETCH_ROWS / 2;
    stripe = (bytes + NGX_HTTP_CACHE_TURBO_SKETCH_HALVE_STRIPES - 1)
             / NGX_HTTP_CACHE_TURBO_SKETCH_HALVE_STRIPES;

    start = ngx_http_cache_turbo_zone_sh(z)->sketch_cursor;

    /* A cursor at or past `bytes` (only possible if sketch_width shrank
     * under us, which it never does post-init, but this is the cheap
     * defensive read) restarts the lap rather than reading out of bounds. */
    if (start >= bytes) {
        start = 0;
    }

    end = start + stripe;

    if (end >= bytes) {
        end = bytes;                 /* last stripe: absorb the remainder */
    }

    for (i = start; i < end; i++) {
        sketch[i] = (u_char) ((sketch[i] >> 1) & 0x77);
    }

    ngx_http_cache_turbo_zone_sh(z)->sketch_ops = 0;

    if (end >= bytes) {
        ngx_http_cache_turbo_zone_sh(z)->sketch_cursor = 0;
        ngx_http_cache_turbo_zone_sh(z)->sketch_gen++;

    } else {
        ngx_http_cache_turbo_zone_sh(z)->sketch_cursor = end;
    }
}


/* Record one access to the key whose row-hashes are `rows` (see
 * ngx_http_cache_turbo_sketch_rows() above -- PERF-AUD2-11: the caller
 * computes this array once, before/outside this call, instead of the four
 * fmix32 avalanches happening fresh inside this critical section).
 *
 * A no-op when the sketch could not be allocated -- see the module.h field
 * block: NULL means "estimate unavailable", never an error.
 *
 * Caller holds the shpool mutex.
 */
void
ngx_http_cache_turbo_shm_sketch_bump(ngx_http_cache_turbo_zone_t *z,
    const uint32_t rows[NGX_HTTP_CACHE_TURBO_SKETCH_ROWS])
{
    ngx_uint_t  row, idx, width;

    if (ngx_http_cache_turbo_zone_sh(z)->sketch == NULL) {
        return;
    }

    width = ngx_http_cache_turbo_zone_sh(z)->sketch_width;

    for (row = 0; row < NGX_HTTP_CACHE_TURBO_SKETCH_ROWS; row++) {
        idx = row * width + (rows[row] & (width - 1));

        ngx_http_cache_turbo_sketch_inc(ngx_http_cache_turbo_zone_sh(z)->sketch, idx);
    }

    ngx_http_cache_turbo_zone_sh(z)->sketch_bumps++;   /* P4-1b: lifetime tally, never reset by halving */

    /* Age on the BUMP count, not on wall-clock time: a quiet zone should not
     * forget what it learned just because an hour passed with no traffic. */
    if (++ngx_http_cache_turbo_zone_sh(z)->sketch_ops >= ngx_http_cache_turbo_zone_sh(z)->sketch_reset_at) {
        ngx_http_cache_turbo_sketch_halve(z);
    }
}


/* Estimated access frequency of the key whose row-hashes are `rows`,
 * 0..SKETCH_MAX. See ngx_http_cache_turbo_sketch_rows() -- PERF-AUD2-11,
 * same rationale as sketch_bump() above.
 *
 * The MIN across the rows: a count-min sketch's error is one-sided, so this
 * can over-estimate on a collision but never under-estimate. Returns 0 when
 * the sketch is unavailable, which is the conservative answer -- stage 2 must
 * read that as "no evidence this key is hot", never as a reason to reject.
 *
 * Caller holds the shpool mutex.
 */
ngx_uint_t
ngx_http_cache_turbo_shm_sketch_estimate(ngx_http_cache_turbo_zone_t *z,
    const uint32_t rows[NGX_HTTP_CACHE_TURBO_SKETCH_ROWS])
{
    ngx_uint_t  row, idx, v, min, width;

    if (ngx_http_cache_turbo_zone_sh(z)->sketch == NULL) {
        return 0;
    }

    width = ngx_http_cache_turbo_zone_sh(z)->sketch_width;
    min = NGX_HTTP_CACHE_TURBO_SKETCH_MAX;

    for (row = 0; row < NGX_HTTP_CACHE_TURBO_SKETCH_ROWS; row++) {
        idx = row * width + (rows[row] & (width - 1));

        v = ngx_http_cache_turbo_sketch_get(ngx_http_cache_turbo_zone_sh(z)->sketch, idx);

        if (v < min) {
            min = v;
        }
    }

    return min;
}


/* --- S8 segmented-LRU linkage helpers ------------------------------------
 *
 * EVERY insert/detach in this file goes through these three, so a node's `seg`
 * field and the queue it is actually threaded on can never disagree. That
 * invariant is what eviction depends on: evict_one() takes a node off the tail
 * of one queue and must be certain the node believed it was there.
 *
 * Caller holds the shpool mutex throughout.
 */

/* Link a node onto the head of the queue its `seg` names. `seg` must already
 * be set; this does not choose a segment. */
static void
ngx_http_cache_turbo_lru_link_head(ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_node_t *ctn)
{
    if (ctn->seg == NGX_HTTP_CACHE_TURBO_SEG_PROTECTED) {
        ngx_queue_insert_head(&ngx_http_cache_turbo_zone_sh(z)->lru_protected, &ctn->lru);
        ngx_http_cache_turbo_zone_sh(z)->n_protected++;

    } else {
        ngx_queue_insert_head(&ngx_http_cache_turbo_zone_sh(z)->lru, &ctn->lru);
    }
}


/* Unlink a node from whichever queue it is on, keeping n_protected in step.
 * Leaves `seg` alone: callers either free the node or re-link it. */
static void
ngx_http_cache_turbo_lru_unlink(ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_node_t *ctn)
{
    ngx_queue_remove(&ctn->lru);

    if (ctn->seg == NGX_HTTP_CACHE_TURBO_SEG_PROTECTED) {
        ngx_http_cache_turbo_zone_sh(z)->n_protected--;
    }
}


/* A brand-new node always enters PROBATION, whatever the feature setting. A
 * first store is an unproven key -- that is precisely what makes a scan
 * unable to evict the hot set. */
static void
ngx_http_cache_turbo_lru_insert_new(ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_node_t *ctn)
{
    ctn->seg = NGX_HTTP_CACHE_TURBO_SEG_PROBATION;

    /* S231-EVICT-BLIND: nodes come from ngx_slab_alloc(), which does NOT zero
     * -- every other field is initialised explicitly by the four creation
     * sites, and this bit must be too. A node born with a garbage sie_spared
     * of 1 reads as "already had its second chance" and is evicted on sight by
     * the very first eviction pass that reaches it, including a cold-miss STUB
     * (shm.c:~1059) whose disappearance strands every waiter on that key until
     * lock_ttl. Initialised here rather than at each creation site because all
     * four funnel through this function, exactly like `seg` above. */
    ctn->sie_spared = 0;

    /* Same rule, same reason: varidx_pending shares the bitfield storage unit
     * above and was added after the sie_spared fix, so it inherited the hole
     * rather than the lesson. Every one of its five writes is a conditional
     * mutation on a node already resident (access.c:818/1376/1472,
     * shm.c:2161, filters.c:1964) -- none of them initialises. A node born on
     * a recycled slab slot with a garbage 1 makes the first lookup
     * (access.c:1375) read it as a dropped variant-index SADD and re-issue a
     * Redis write for a key that never had one, so cold-miss traffic turns
     * into spurious L2 writes and varidx_reissues climbs past varidx_drops. */
    ctn->varidx_pending = 0;

    ngx_queue_insert_head(&ngx_http_cache_turbo_zone_sh(z)->lru, &ctn->lru);
    ngx_http_cache_turbo_zone_sh(z)->n_entries++;
}


/* Cap on demotions performed by ONE call to lru_enforce_cap().
 *
 * This runs on the hot touch_lru() path while holding the shpool mutex, so an
 * unbounded loop is a latency spike an attacker can steer: a burst of stores
 * that pushes n_protected far over cap (e.g. a protected_pct config reload
 * shrinking the segment while it is full) makes one unlucky request pay for
 * unwinding all of it. Bounding the pass to a small, fixed amount of work
 * keeps worst-case call latency flat; the cap converges over subsequent calls
 * rather than in one, since it is safe for n_protected to sit above cap
 * between calls -- nothing reads n_protected except this function, and no
 * caller assumes the cap holds the instant this returns (S231-PERF-LRUCAP). */
#define NGX_HTTP_CACHE_TURBO_LRU_CAP_MAX_EVICT  8

/* Enforce the protected-segment cap by demoting protected tails to the
 * PROBATION HEAD (not tail -- a demoted-but-hot entry deserves a second
 * chance before a cold probation entry). Caller holds the shpool mutex.
 *
 * A loop, not an `if`: protected_pct can shrink across a reload while entries
 * are already resident, so more than one demotion may be owed. It is bounded
 * by n_protected and each pass strictly decrements it, so it terminates --
 * and additionally capped at NGX_HTTP_CACHE_TURBO_LRU_CAP_MAX_EVICT per call
 * so it terminates quickly, not just eventually. */
static void
ngx_http_cache_turbo_lru_enforce_cap(ngx_http_cache_turbo_zone_t *z,
    ngx_uint_t protected_pct)
{
    ngx_uint_t                    cap;
    ngx_uint_t                    demoted;
    ngx_queue_t                  *q;
    ngx_http_cache_turbo_node_t  *victim;

    /* Round UP, and floor the result at 1.
     *
     * Truncating division would make the cap 0 for any zone with fewer than
     * 100/pct entries -- at the default 80 that is a zone of ONE entry, whose
     * single node would be promoted and instantly demoted again on every hit,
     * churning the queues forever and never actually protecting anything. The
     * floor guarantees a non-empty zone can always protect at least one entry,
     * which is what makes the segment meaningful on small zones. */
    cap = (ngx_http_cache_turbo_zone_sh(z)->n_entries * protected_pct + 99) / 100;

    if (cap == 0) {
        cap = 1;
    }

    demoted = 0;

    while (ngx_http_cache_turbo_zone_sh(z)->n_protected > cap
           && !ngx_queue_empty(&ngx_http_cache_turbo_zone_sh(z)->lru_protected)
           && demoted < NGX_HTTP_CACHE_TURBO_LRU_CAP_MAX_EVICT)
    {
        demoted++;

        q = ngx_queue_last(&ngx_http_cache_turbo_zone_sh(z)->lru_protected);
        victim = ngx_queue_data(q, ngx_http_cache_turbo_node_t, lru);

        ngx_http_cache_turbo_lru_unlink(z, victim);
        victim->seg = NGX_HTTP_CACHE_TURBO_SEG_PROBATION;
        ngx_http_cache_turbo_lru_link_head(z, victim);
    }
}


/* Re-splice a node on access, and promote it on its second touch (S8).
 *
 * Shared by all three re-splice sites (fresh HIT, stale HIT, memo consult) so
 * the promotion rule cannot drift between them -- a rule duplicated three
 * times is a rule that is wrong at one of them.
 *
 * `protected_pct` of 0 means the feature is OFF: the node then simply re-heads
 * within probation, which is byte-for-byte the pre-S8 behaviour.
 *
 * Returns with the node re-headed on whichever queue it now belongs to.
 * Caller holds the shpool mutex.
 */
void
ngx_http_cache_turbo_shm_touch_lru(ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_node_t *ctn, time_t now, ngx_uint_t protected_pct,
    uint32_t hash)
{
    /* P4-1a: record the access in the frequency sketch BEFORE the coarse gate
     * below.
     *
     * ⚠ The order is load-bearing, not stylistic. The gate returns early when
     * this node was touched within the last second, so a bump placed AFTER it
     * would count at most one access per key per second -- which undercounts
     * hot keys by exactly the factor that makes them hot, and would leave the
     * sketch unable to distinguish a key served 500 times a second from one
     * served once. The whole point of the estimate is that ratio.
     *
     * ⚠ COST, accepted deliberately. This reintroduces a shared-cacheline
     * write on the hot path, which is what the P1 gate was added to remove
     * (see the rationale in module.h's last_access field block). The write is
     * to the SKETCH ARRAY, not to the node -- so it does not dirty the node
     * cacheline readers are walking, and it lands in one of `sketch_width`
     * slots rather than on a single hot word. It is still a real write under
     * the shpool mutex the caller already holds, and it is taken on purpose:
     * stage 2's admission test is worth nothing on undercounted data.
     *
     * C4: the sketch is (deliberately, see shm_admit) keyed on the real
     * 32-bit crc32 short hash, not on the node's widened rbtree key --
     * `ctn->node.key` no longer equals crc32(key) once the rbtree key is
     * derived from key_hash instead. Every caller of this function already
     * has the real hash in scope (it is how it found `ctn` in the first
     * place), so it is threaded straight through rather than recomputed.
     *
     * PERF-AUD2-11: derive the 4 row-hashes once here rather than letting
     * sketch_bump() recompute them internally from `hash`. */
    {
        uint32_t  rows[NGX_HTTP_CACHE_TURBO_SKETCH_ROWS];

        ngx_http_cache_turbo_sketch_rows(hash, rows);
        ngx_http_cache_turbo_shm_sketch_bump(z, rows);
    }

    /* P1 coarse gate: at most one LRU write per node per second. Deliberately
     * the SAME gate that governed the flat re-splice -- S8 adds no second
     * clock, so a hot key still serializes readers at most once/second. */
    if (now - ctn->last_access < 1) {
        return;
    }

    ctn->last_access = now;

    ngx_http_cache_turbo_lru_unlink(z, ctn);

    /* Promote on the SECOND touch, and only ever an ENTRY.
     *
     * ⚠ COUNTER nodes (min_uses counters, L13 negative memos, cold-miss stubs)
     * must stay in probation permanently. They hold bookkeeping, not content;
     * promoting one would let an L2 miss storm pin the protected segment with
     * nodes that carry no body at all -- inverting the feature. The kind gate
     * is load-bearing, not defensive.
     *
     * "Second touch" is read off `seg`: a node still in probation that is being
     * touched has been accessed at least once since it was stored (the store
     * itself does not touch), so this touch is the promoting one. That reuses
     * the existing state instead of adding a hit counter to the node. */
    if (protected_pct == 0) {
        /* Feature OFF: DEMOTE, do not merely decline to promote.
         *
         * ⚠ A zone survives a reload (init_zone inherits the live `sh` when
         * `octx` is set, or `shm.exists`), so an `on` -> `off` config change
         * hands us nodes that are already PROTECTED. Leaving `seg` alone here
         * would relink them onto lru_protected forever -- `off` would stop
         * future promotions but never restore the flat single-queue LRU, and
         * the entries promoted while it was on would stay preferentially
         * un-evictable for the life of the zone. Demoting on touch drains the
         * protected queue back into probation as those nodes are used, so
         * `off` genuinely converges on the pre-S8 behaviour. Untouched nodes
         * are reached by eviction instead, which drains lru_protected once
         * probation empties. (CodeRabbit, PR #81.) */
        ctn->seg = NGX_HTTP_CACHE_TURBO_SEG_PROBATION;

    } else if (ctn->kind == NGX_HTTP_CACHE_TURBO_NODE_ENTRY
               && ctn->seg == NGX_HTTP_CACHE_TURBO_SEG_PROBATION
               && ctn->promotable)
    {
        ctn->seg = NGX_HTTP_CACHE_TURBO_SEG_PROTECTED;
    }

    ctn->promotable = 1;

    ngx_http_cache_turbo_lru_link_head(z, ctn);

    if (protected_pct > 0) {
        ngx_http_cache_turbo_lru_enforce_cap(z, protected_pct);
    }
}


/* Little-endian u32/u64 readers, duplicated from the `static` helpers of the
 * same name in ngx_http_cache_turbo_module.c (not visible across TUs) so this
 * file can read the CTB5 wire header's `created`/`sie_ttl` fields without
 * threading a request ctx through -- see ngx_http_cache_turbo_shm_node_sie_live()
 * just below for why. Same wire offsets, same byte order; keep in sync with
 * the CTB5 layout comment in ngx_http_cache_turbo_module.h. */
static ngx_inline uint32_t
ngx_http_cache_turbo_shm_get_u32(const u_char *p)
{
    return (uint32_t) p[0]
         | ((uint32_t) p[1] << 8)
         | ((uint32_t) p[2] << 16)
         | ((uint32_t) p[3] << 24);
}

static ngx_inline uint64_t
ngx_http_cache_turbo_shm_get_u64(const u_char *p)
{
    return (uint64_t) ngx_http_cache_turbo_shm_get_u32(p)
         | ((uint64_t) ngx_http_cache_turbo_shm_get_u32(p + 4) << 32);
}


/* S231-EVICT-BLIND: is `ctn` a live stale-if-error entry right now? Only an
 * ENTRY carries a blob (a COUNTER's `data` is NULL / not a CTB5 blob), and
 * only while `now` is still inside the absolute (created + sie_ttl) window --
 * the identical test the request path uses to decide whether to arm an SIE
 * snapshot (ngx_http_cache_turbo_module.c, the `ctx->sie_armed` arm site).
 * Duplicated here rather than shared because that site works off a live
 * request's `ctx`/blob-header parse and this one only has the raw node under
 * the shpool mutex -- same offsets (24 = created, 40 = sie_ttl), same wire
 * format, no ctx to thread through.
 */
static ngx_flag_t
ngx_http_cache_turbo_shm_node_sie_live(ngx_http_cache_turbo_node_t *ctn,
    time_t now)
{
    time_t    created;
    uint32_t  sie_ttl;

    if (ctn->kind != NGX_HTTP_CACHE_TURBO_NODE_ENTRY || ctn->data == NULL) {
        return 0;
    }

    created  = (time_t) ngx_http_cache_turbo_shm_get_u64(ctn->data + 24);
    sie_ttl  = ngx_http_cache_turbo_shm_get_u32(ctn->data + 40);

    return sie_ttl > 0 && now < created + (time_t) sie_ttl;
}


/* P4-1b: W-TinyLFU ADMISSION. Answer "should this NEW key be admitted?".
 * Returns 1 = admit, 0 = refuse. Caller holds the shpool mutex.
 *
 * The decision, and only this: a candidate is refused when the frequency
 * sketch says it is STRICTLY COLDER than the entry the zone would have to
 * give up to make room for it -- the probation tail, which is exactly the
 * node ngx_http_cache_turbo_shm_evict_one() takes first. Without this, a
 * one-hit wonder ALWAYS displaces a resident entry: eviction here is 100%
 * recency and there is no other place that says no.
 *
 * ⚠ THE TERMINATION ARGUMENT -- why a policy that can REJECT cannot make
 *   ngx_http_cache_turbo_shm_alloc_evict() spin.
 *
 *   alloc_evict()'s loop is `while (p == NULL && evict_one(z))`. It spins
 *   forever only if evict_one() keeps claiming progress without freeing
 *   anything. This function is NOT in that loop and never will be: it is
 *   called ONCE, by store_locked(), strictly BEFORE alloc_evict() is entered,
 *   and its answer is a plain early `return NGX_DECLINED` from store_locked().
 *   A refusal therefore REMOVES an alloc_evict() call rather than adding an
 *   iteration to one, and cannot alter evict_one()'s per-call progress
 *   guarantee (which is what the contract at the head of evict_one() states).
 *
 *   The inverse hazard -- a refusal LOOP, where the caller retries the store
 *   hoping for a different answer -- is closed by the same shape: store_locked
 *   returns to its caller, which propagates the refusal up as a
 *   store-declined, and nothing in this module re-drives a store on
 *   NGX_DECLINED. There is no retry to bound.
 *
 *   Both properties are pinned by test_p4_1b_admission_never_spins().
 *
 * FAIL-OPEN, in three independent directions, because a wrongly refused
 * store is a silent permanent cache miss:
 *   - policy off (the shipped default)            -> admit
 *   - sketch unavailable (NULL / never allocated) -> admit; estimate() returns
 *     0 for BOTH sides there, and 0 < 0 is false, but the explicit test says
 *     so rather than relying on that arithmetic
 *   - nothing resident to displace (probation empty) -> admit. Refusing here
 *     would let a cold zone refuse to fill itself, and there is no victim to
 *     be colder than.
 *
 * Ties ADMIT (strict <). A sketch estimate is one-sided (it over-counts on a
 * collision, never under-counts), so equality is the ambiguous case and the
 * ambiguous answer is the fail-open one.
 */
static ngx_int_t
ngx_http_cache_turbo_shm_admit(ngx_http_cache_turbo_zone_t *z, uint32_t hash)
{
    ngx_queue_t                  *q;
    ngx_http_cache_turbo_node_t  *victim;
    ngx_uint_t                    cand_freq, victim_freq;
    uint32_t                      rows[NGX_HTTP_CACHE_TURBO_SKETCH_ROWS];

    if (!ngx_http_cache_turbo_zone_sh(z)->admission) {
        return 1;                    /* policy off: the shipped default */
    }

    if (ngx_http_cache_turbo_zone_sh(z)->sketch == NULL) {
        return 1;                    /* no evidence is never a reason to refuse */
    }

    if (ngx_queue_empty(&ngx_http_cache_turbo_zone_sh(z)->lru)) {
        /* No probation victim. Deliberately NOT falling through to the
         * protected tail: refusing a candidate on behalf of an entry that has
         * already proven itself twice would make an all-protected zone
         * un-fillable, and the protected tail is not what evict_one() would
         * take first anyway. */
        return 1;
    }

    q = ngx_queue_last(&ngx_http_cache_turbo_zone_sh(z)->lru);
    victim = ngx_queue_data(q, ngx_http_cache_turbo_node_t, lru);

    /* PERF-AUD2-11: derive each hash's 4 row-hashes once and pass the array
     * in, rather than letting sketch_estimate() recompute them internally --
     * the candidate's `hash` and the victim's `hash_crc32` are two distinct
     * values, so this is two separate row-hash derivations, each now
     * computed exactly once instead of once per row inside the estimate
     * call. */
    ngx_http_cache_turbo_sketch_rows(hash, rows);
    cand_freq   = ngx_http_cache_turbo_shm_sketch_estimate(z, rows);
    /* C4: the sketch is populated (touch_lru's sketch_bump) and queried
     * (`hash` just above) in real-crc32 space, never in the widened rbtree
     * key's space -- `victim->node.key` stopped being that crc32 once the
     * rbtree key was derived from key_hash instead (see
     * ngx_http_cache_turbo_shm_key64()). A bare cast here would silently
     * requery the sketch at an unrelated 32-bit value: not a truncation of
     * the SAME number, a DIFFERENT one, drawn from the low 32 bits of an
     * 8-byte prefix of key_hash rather than from the candidate's hash space
     * at all.
     *
     * PERF-AUD2-10: every node-init site (store_locked/claim_locked/
     * count_miss_locked/l2_neg_set) now stamps ctn->hash_crc32 with exactly
     * this value at creation time -- the same `hash` parameter each of them
     * already received and previously discarded, which by construction
     * equals ngx_crc32_short(key, 32) for that node's own `key` (every
     * caller of the public store/claim/count_miss/l2_neg_set entry points
     * derives `hash` from the same key_hash via ngx_crc32_short() before
     * calling; see shm_touch_lru()'s C4 comment for the same invariant used
     * on the candidate side). Reading it back here is therefore
     * byte-identical to the recompute it replaces, without the 32-byte
     * ngx_memcmp-per-level rbtree-adjacent crc32 pass under the lock. */
    ngx_http_cache_turbo_sketch_rows(victim->hash_crc32, rows);
    victim_freq = ngx_http_cache_turbo_shm_sketch_estimate(z, rows);

    if (cand_freq < victim_freq) {
        ngx_http_cache_turbo_zone_sh(z)->admission_refused++;
        return 0;
    }

    return 1;
}


/* Evict the least-recently-used entry. Caller holds the shpool mutex. Returns 1
 * if an entry was evicted, 0 if nothing was evictable (no candidate).
 *
 * ⚠ THE HANG HAZARD. With two queues, `ngx_queue_empty(&z->sh->lru)` is no
 * longer the "nothing to evict" test in either direction:
 *
 *   - Returning 0 while lru_protected still holds a victim makes alloc_evict()
 *     give up on a zone that still had reclaimable entries (a store fails for
 *     no reason).
 *   - Returning non-zero WITHOUT evicting makes alloc_evict()'s
 *     `while (p == NULL && evict_one(z))` spin forever -- while holding
 *     shpool->mutex. That wedges the worker and every other worker behind it.
 *     It is not a crash and not a wrong number; a black-box suite sees only a
 *     timeout.
 *
 * So: probation tail first (that ordering IS the scan resistance), fall
 * through to the protected tail, and return 0 only when BOTH are empty.
 * Pinned by test_s8_evict_terminates_on_empty_queues() under a SIGALRM
 * watchdog, so a regression fails in bounded time instead of hanging CI.
 *
 * S231-EVICT-BLIND: while the breaker is OPEN, a live-SIE tail candidate is
 * given ONE second chance instead of being taken -- its `sie_spared` bit is
 * set and the walk moves to the next tail candidate (same queue, then falls
 * through to the other queue exactly as before). A candidate whose bit is
 * ALREADY set is taken unconditionally, spared or not. This is why the
 * "skip every live-SIE entry" design was rejected in favour of this one:
 * during an outage every resident entry can be SIE-live, and an unconditional
 * skip would make BOTH queues look candidate-less to this function while
 * neither is actually empty -- the exact hang the two-queue fallthrough above
 * exists to avoid, just moved one level up. Sparing at most once per node
 * bounds the walk by 2 * n_entries, so it still always terminates and a
 * store during an OPEN-breaker outage still succeeds instead of failing
 * closed. Reading breaker_state here is a raw unpack, never
 * ngx_http_cache_turbo_shm_breaker_state() -- that call TRANSITIONS the
 * state machine and must not be invoked from an unrelated eviction walk. */
static ngx_int_t
ngx_http_cache_turbo_shm_evict_one(ngx_http_cache_turbo_zone_t *z)
{
    ngx_queue_t                  *queues[2];
    ngx_queue_t                  *head;
    ngx_queue_t                  *q;
    ngx_queue_t                  *prev;
    ngx_queue_t                  *fallback;
    ngx_http_cache_turbo_node_t  *ctn;
    ngx_flag_t                     breaker_open;
    time_t                        now;
    ngx_uint_t                    i;

    breaker_open = ngx_http_cache_turbo_brk_state(ngx_http_cache_turbo_zone_sh(z)->breaker_state)
                   == NGX_HTTP_CACHE_TURBO_BREAKER_OPEN;
    now = ngx_time();

    /* Probation tail first (that ordering IS the scan resistance), protected
     * tail second. Walking each queue tail-to-head (oldest candidate first),
     * and within a queue skipping over an already-spared-once live-SIE node
     * to the next-oldest. Bounded by n_entries per queue -- each node is
     * visited at most twice total across the whole function (once to spare
     * it, once more to take it on a LATER call) -- so this always
     * terminates, satisfying the same contract the caller relies on. */
    queues[0] = &ngx_http_cache_turbo_zone_sh(z)->lru;
    queues[1] = &ngx_http_cache_turbo_zone_sh(z)->lru_protected;

    for (i = 0; i < 2; i++) {
        head = queues[i];

        if (ngx_queue_empty(head)) {
            continue;
        }

        /* fallback remembers the OLDEST (tail) candidate in this queue: if
         * every candidate turns out to need sparing on THIS pass (a queue
         * that is entirely fresh live-SIE nodes -- the exact state a real
         * outage's first eviction ever sees), sparing everyone once and then
         * reporting "nothing evictable" would still wedge alloc_evict() on
         * the very first store, identical to the rejected unconditional-skip
         * design just delayed by one full queue walk. So once every
         * candidate has been offered its one-time spare, this call falls
         * back to taking the tail anyway -- it is guaranteed sie_spared by
         * then, exactly the state a LATER call would evict it in, just
         * reached within this same call instead of a subsequent one. */
        fallback = ngx_queue_last(head);

        for (q = ngx_queue_last(head); q != head; q = prev) {
            ctn = ngx_queue_data(q, ngx_http_cache_turbo_node_t, lru);

            if (breaker_open && !ctn->sie_spared
                && ngx_http_cache_turbo_shm_node_sie_live(ctn, now))
            {
                /* Live-SIE candidate, breaker OPEN, not yet spared: spare it
                 * once and try the next-oldest node in this same queue. */
                ctn->sie_spared = 1;
                prev = ngx_queue_prev(q);
                continue;
            }

            /* Evictable: not SIE-live, breaker CLOSED/HALF_OPEN, or already
             * spared once before. */
            ngx_http_cache_turbo_lru_unlink(z, ctn);
            ngx_http_cache_turbo_zone_sh(z)->n_entries--;
            ngx_rbtree_delete(&ngx_http_cache_turbo_zone_sh(z)->rbtree, &ctn->node);

            /* C3: this generic LRU walk evicts ANY kind, markers included --
             * see the `markers` field comment in module.h. */
            if (ctn->kind == NGX_HTTP_CACHE_TURBO_NODE_MARKER) {
                (void) ngx_atomic_fetch_add(
                    &ngx_http_cache_turbo_zone_sh(z)->markers, -1);
            }

            if (ctn->data) {
                ngx_http_cache_turbo_blob_node_release(z, ctn->data);
            }
            ngx_http_cache_turbo_shm_free_locked(z, ctn,
                sizeof(ngx_http_cache_turbo_node_t));

            (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->evictions, 1);
            return 1;
        }

        /* Every node in this queue was freshly spared this call, none was
         * already-spared -- take the fallback (the tail, now sie_spared)
         * rather than leaving a full queue of reclaimable memory unreported. */
        ctn = ngx_queue_data(fallback, ngx_http_cache_turbo_node_t, lru);

        ngx_http_cache_turbo_lru_unlink(z, ctn);
        ngx_http_cache_turbo_zone_sh(z)->n_entries--;
        ngx_rbtree_delete(&ngx_http_cache_turbo_zone_sh(z)->rbtree, &ctn->node);

        /* C3: fallback-take arm of the same generic walk -- see the sibling
         * comment on the probation-tail take above. */
        if (ctn->kind == NGX_HTTP_CACHE_TURBO_NODE_MARKER) {
            (void) ngx_atomic_fetch_add(
                &ngx_http_cache_turbo_zone_sh(z)->markers, -1);
        }

        if (ctn->data) {
            ngx_http_cache_turbo_blob_node_release(z, ctn->data);
        }
        ngx_http_cache_turbo_shm_free_locked(z, ctn,
            sizeof(ngx_http_cache_turbo_node_t));

        (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->evictions, 1);
        return 1;
    }

    return 0;                        /* genuinely nothing to evict */
}


/* Slab-alloc `size` bytes, evicting LRU entries one at a time until the
 * allocation succeeds or no candidate remains (PERF-6). A single fragmented
 * allocation could previously fail even when several reclaimable entries would
 * together free enough space; this drains as many as needed. Caller holds the
 * shpool mutex; any node that must NOT be evicted (e.g. the one being refreshed)
 * must be detached from the LRU before calling. */
static void *
ngx_http_cache_turbo_shm_alloc_evict(ngx_http_cache_turbo_zone_t *z, size_t size)
{
    void  *p;

#ifdef NGX_TEST_HARNESS
    /* S24: probe-armed slab-allocation fault, for testkit's `fault_slab=N`
     * arm query. See ngx_http_cache_turbo_probe.c's fault_set hook for the
     * arming side and module.h's fault_slab_countdown for the encoding
     * (NGX_HTTP_CACHE_TURBO_FAULT_DISARMED == disarmed; a non-negative value
     * is a since-armed countdown of attempts through this funnel).
     *
     * WHY THE INJECTION IS *HERE* AND NOT AT THE ngx_slab_alloc_locked() CALL.
     *   Forcing the first ngx_slab_alloc_locked() to return NULL injects
     *   NOTHING. This function's entire job is to survive that: on NULL it
     *   evicts an LRU victim and retries, and against a zone holding anything
     *   evictable the retry succeeds. The caller would then see a perfectly
     *   ordinary non-NULL return, the error path under test would never be
     *   entered, and the scenario would report green having exercised the
     *   happy path -- with the added insult of a real cache entry destroyed to
     *   make room. A fault the code under test routinely recovers from is not
     *   a fault; it is a slow allocation.
     *
     *   The honest injection is the one that makes the WHOLE funnel answer
     *   NULL, which is the only answer any caller of this function has an
     *   error path for. Returning before the allocator is consulted at all
     *   also leaves the zone exactly as it was found: nothing evicted,
     *   used_bytes unmoved, no slab state perturbed. That matters for the
     *   oracle this exists to feed -- a resource-delta comparison across the
     *   faulting request cannot tell a leak from collateral eviction if the
     *   fault path is allowed to mutate the zone on its way out.
     *
     * PLAIN READ-MODIFY-WRITE, NOT AN ATOMIC, AND THAT IS NOT AN OVERSIGHT.
     *   Every caller of this function holds the shpool mutex (stated in the
     *   contract comment above, and structurally true: the function calls
     *   ngx_slab_alloc_LOCKED). The field is therefore mutex-protected here
     *   exactly like used_bytes two lines below, and a cmp-set loop would buy
     *   nothing but the false impression that this path is lock-free. The
     *   field is still declared ngx_atomic_t because the ARMING side --
     *   fault_set, called from a probe request -- deliberately does not take
     *   the zone mutex, for the same reason the zone_render hook does not.
     *
     * ONE ARM, EXACTLY ONE INJECTED FAILURE. The attempt that finds the
     * countdown at 0 fails and disarms in the same critical section, so no
     * follow-up disarm request is needed and no second worker can trip the
     * same arm. Attempts made while disarmed touch nothing. */
    {
        ngx_atomic_t  *fc =
            &ngx_http_cache_turbo_zone_sh(z)->fault_slab_countdown;

        if (*fc != NGX_HTTP_CACHE_TURBO_FAULT_DISARMED) {
            if (*fc == 0) {
                *fc = NGX_HTTP_CACHE_TURBO_FAULT_DISARMED;
                return NULL;
            }
            (*fc)--;
        }
    }
#endif

    p = ngx_slab_alloc_locked(ngx_http_cache_turbo_zone_pool(z), size);

    while (p == NULL && ngx_http_cache_turbo_shm_evict_one(z)) {
        p = ngx_slab_alloc_locked(ngx_http_cache_turbo_zone_pool(z), size);
    }

    /* P4-2-s3a: this is the SOLE allocation funnel for cached payload+metadata
     * (every node alloc and, via blob_alloc(), every body alloc goes through
     * here), so charging the used-bytes gauge here -- and discharging it in
     * shm_free_locked(), the matching sole free funnel -- makes the pairing
     * structural rather than a per-site audit. Caller holds the shpool mutex,
     * same as every other z->sh field that is not an atomic. */
    if (p != NULL) {
        ngx_http_cache_turbo_zone_sh(z)->used_bytes += size;
    }

    return p;
}


/* P4-2-s3a: discharge counterpart of shm_alloc_evict(). `size` MUST be the
 * exact value passed to the alloc that produced `p`. Caller holds the shpool
 * mutex. The assert-shaped guard is not a silent clamp: an underflow here means
 * a charge/discharge pair is mismatched, which is a bug in the pairing -- the
 * gauge is pinned to 0 so it cannot wrap into a nonsense multi-exabyte reading,
 * and the condition is logged at ALERT so it is not swallowed. */
static void
ngx_http_cache_turbo_shm_free_locked(ngx_http_cache_turbo_zone_t *z, void *p,
    size_t size)
{
    if (ngx_http_cache_turbo_zone_sh(z)->used_bytes >= size) {
        ngx_http_cache_turbo_zone_sh(z)->used_bytes -= size;

    } else {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                      "cache_turbo: used_bytes underflow "
                      "(have %uz, discharging %uz) -- charge/discharge pairing "
                      "bug", (size_t) ngx_http_cache_turbo_zone_sh(z)->used_bytes, size);
        ngx_http_cache_turbo_zone_sh(z)->used_bytes = 0;
    }

    ngx_slab_free_locked(ngx_http_cache_turbo_zone_pool(z), p);
}


/* Remove one node from rbtree + LRU and free its slab memory. Caller holds the
 * shpool mutex. */
static void
ngx_http_cache_turbo_shm_drop_locked(ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_node_t *ctn)
{
    ngx_http_cache_turbo_lru_unlink(z, ctn);
    ngx_http_cache_turbo_zone_sh(z)->n_entries--;
    ngx_rbtree_delete(&ngx_http_cache_turbo_zone_sh(z)->rbtree, &ctn->node);
    /* C3: the shared drop path for purge_key() (a single explicit key,
     * including the vary-marker purge at access.c's PURGE self-heal site) and
     * purge_all() (every node, unconditionally) -- either can drop a marker,
     * so this is one of the four node-free sites the `markers` counter must
     * cover. See the field comment in module.h. */
    if (ctn->kind == NGX_HTTP_CACHE_TURBO_NODE_MARKER) {
        (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->markers, -1);
    }
    if (ctn->data) {
        ngx_http_cache_turbo_blob_node_release(z, ctn->data);
    }
    ngx_http_cache_turbo_shm_free_locked(z, ctn,
        sizeof(ngx_http_cache_turbo_node_t));
}


ngx_int_t
ngx_http_cache_turbo_shm_purge_key(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash)
{
    ngx_http_cache_turbo_node_t  *ctn;

    ngx_shmtx_lock(ngx_http_cache_turbo_zone_mutex(z));
    ctn = ngx_http_cache_turbo_shm_lookup(z, key_hash, hash);
    if (ctn == NULL) {
        ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));
        return 0;
    }
    ngx_http_cache_turbo_shm_drop_locked(z, ctn);
    ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));
    return 1;
}


/* PERF-3: how many nodes to drop per lock acquisition during a purge-all walk.
 * Holding the zone mutex for the ENTIRE LRU (which can be millions of entries)
 * blocks every other worker's cache lookups/stores for the whole walk. Dropping
 * in bounded batches and releasing the mutex between them keeps each critical
 * section short, so a concurrent request waits at most one batch, not the whole
 * purge. The total is still reported. */
#define NGX_HTTP_CACHE_TURBO_PURGE_BATCH  512

ngx_uint_t
ngx_http_cache_turbo_shm_purge_all(ngx_http_cache_turbo_zone_t *z)
{
    ngx_uint_t                    n = 0, batch;
    ngx_queue_t                  *q;
    ngx_http_cache_turbo_node_t  *ctn;

    for ( ;; ) {
        ngx_shmtx_lock(ngx_http_cache_turbo_zone_mutex(z));

        batch = 0;

        /* ⚠ S8: BOTH queues must drain. Walking only &z->sh->lru would leave
         * the entire protected set resident and a purge would silently keep
         * serving the objects it claimed to remove -- the classic fan-out
         * miss. Probation first, then protected; the batch cap spans the two
         * so the mutex is still released every PURGE_BATCH drops however the
         * entries are distributed. */
        while (batch < NGX_HTTP_CACHE_TURBO_PURGE_BATCH
               && !ngx_queue_empty(&ngx_http_cache_turbo_zone_sh(z)->lru))
        {
            q = ngx_queue_head(&ngx_http_cache_turbo_zone_sh(z)->lru);
            ctn = ngx_queue_data(q, ngx_http_cache_turbo_node_t, lru);
            ngx_http_cache_turbo_shm_drop_locked(z, ctn);
            batch++;
        }

        while (batch < NGX_HTTP_CACHE_TURBO_PURGE_BATCH
               && !ngx_queue_empty(&ngx_http_cache_turbo_zone_sh(z)->lru_protected))
        {
            q = ngx_queue_head(&ngx_http_cache_turbo_zone_sh(z)->lru_protected);
            ctn = ngx_queue_data(q, ngx_http_cache_turbo_node_t, lru);
            ngx_http_cache_turbo_shm_drop_locked(z, ctn);
            batch++;
        }

        n += batch;
        ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));

        /* Drained, or this batch hit the cap with more to go: loop and let any
         * waiter take the mutex before we grab the next batch. */
        if (batch < NGX_HTTP_CACHE_TURBO_PURGE_BATCH) {
            break;
        }
    }

    return n;
}


/* AUD-L2-PROMOTE-RACE / AUD-5XX-CTA: the body of what used to be
 * ngx_http_cache_turbo_shm_store(), with its own lock/unlock removed. Runs
 * with the zone mutex ALREADY HELD by the caller, so store() and store_if()
 * can share it -- store_if() adds its predicate check under the SAME lock
 * acquisition that performs the write, closing the check-then-act window a
 * separate lookup-then-store pair leaves open. Behaviour is byte-identical
 * to the pre-refactor store(): every `unlock; return X` below is exactly
 * where store()'s used to be, now just `return X`.
 *
 * PERF-AUD2-09: `ctn` is a caller-resolved lookup result, exactly the same
 * shape S231-PERF-MISSLOCKS gave count_miss_locked()/claim_locked() --
 * see those functions' own comments for the pattern this follows. A caller
 * that already did its own ngx_http_cache_turbo_shm_lookup() under the SAME
 * lock hold (store_marker(), store_if()) passes that result straight
 * through instead of this function repeating the rbtree descent for a key
 * it already resolved a moment earlier. A caller with no prior lookup
 * (store()) passes NULL and this function does its own, exactly as before
 * -- the NULL branch below is byte-identical to the old unconditional
 * lookup.
 *
 * `out_ctn`, if non-NULL, receives the node this call wrote on NGX_OK (the
 * refreshed resident node, or the freshly allocated one) -- unset on every
 * other return. store_marker() uses this to retag `kind` on the node it
 * just wrote without a THIRD lookup: the refresh path reuses the same `ctn`
 * the caller passed in, and the new-entry path allocates one the caller had
 * no way to already hold. Pass NULL to skip (store()/store_if() have no use
 * for it -- neither retags the node after the write). Every read/mutate/
 * return past this point is otherwise untouched: only where `ctn` comes
 * from, and this one extra out-write on the OK paths, changed. */
static ngx_int_t
ngx_http_cache_turbo_shm_store_locked(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, u_char *data, size_t len,
    time_t fresh_ttl, time_t stale_ttl, ngx_http_cache_turbo_node_t *ctn,
    ngx_http_cache_turbo_node_t **out_ctn)
{
    u_char                       *body;
    time_t                        now;

    /* fresh_ttl may be <= 0 (object already stale on an L2 fill) — fresh_until
     * then lands in the past and the node is served via the stale path. stale_ttl
     * is the absolute serveable window from now (0 = no stale serving). */
    now = ngx_time();

    /* Already present? Update in place (refresh path). PERF-AUD2-09: only
     * look it up ourselves when the caller did not already hand us the
     * result of one under this same lock hold. */
    if (ctn == NULL) {
        ctn = ngx_http_cache_turbo_shm_lookup(z, key_hash, hash);
    }

    if (ctn) {
        /* Detach ctn from the LRU *before* any eviction. shm_evict_one() frees
         * the LRU tail, and on a stale refresh ctn may itself be that tail;
         * evicting it here would free the very node we go on to write to
         * (use-after-free + double-free of ctn->data). Detaching guarantees the
         * retry-evict frees some OTHER node (or none, if ctn was the only one).
         * Re-inserted at the LRU head on success, restored on alloc fail.
         *
         * ⚠ S8: unlink/relink both go through the helpers so n_protected stays
         * in step with the linkage on BOTH exits. `seg` is left untouched
         * across the detach, so the restore path below puts the node back on
         * exactly the queue it came off -- a protected entry whose refresh
         * fails must not silently demote itself. */
        ngx_http_cache_turbo_lru_unlink(z, ctn);

        body = ngx_http_cache_turbo_blob_alloc(z, len);
        if (body == NULL) {
            /* Refresh failed: keep the existing (stale) entry reachable, on
             * its original segment. */
            ngx_http_cache_turbo_lru_link_head(z, ctn);
            return NGX_ERROR;
        }

        ngx_memcpy(body, data, len);
        if (ctn->data) {
            /* PERF-7: the old blob may have an in-flight zero-copy server; this
             * detaches it and frees only if no serve holds it (else the server's
             * cleanup frees it). The new blob is independent, so a concurrent
             * serve of the old one is unaffected. */
            ngx_http_cache_turbo_blob_node_release(z, ctn->data);
        }
        ctn->kind = NGX_HTTP_CACHE_TURBO_NODE_ENTRY;  /* now holds a body */
        ctn->data = body;
        ctn->len = len;
        ctn->fresh_until = now + fresh_ttl;
        ctn->stale_until = stale_ttl ? now + stale_ttl : 0;
        ctn->refreshing = 0;
        ctn->refresh_lock_until = 0;
        /* CTXRDR-ADOPT-LEASE: the store RESOLVES the lease, so it ends here for
         * whoever held it. Clearing the token is what stops a later unstub() or
         * adoption from matching a lease this node no longer has -- and, once the
         * node is re-leased, from matching the NEXT holder's. */
        ctn->refresh_owner = 0;
        ctn->l2_neg_until = 0;       /* L13: node now holds a body; any memo it
                                      * carried as a COUNTER is moot */
        ctn->last_access = now;      /* P1: store re-heads the LRU, sync stamp */

        /* S8: a refresh installs a NEW representation, so it re-earns
         * protection rather than inheriting the old body's. The node is
         * ALREADY unlinked (detached above, before the alloc), so this only
         * re-labels it and links it back onto probation. Two further hits
         * protect it again. This also stops the refresh path being a way to
         * hold protected residency indefinitely without ever being read. */
        ctn->seg = NGX_HTTP_CACHE_TURBO_SEG_PROBATION;
        ctn->promotable = 0;

        /* S231-EVICT-BLIND: a refresh installs a new representation with its
         * own SIE window, so it re-earns its second chance rather than
         * inheriting a spare already consumed by the body it replaced. This
         * node is reused in place (not freshly allocated), so lru_insert_new()
         * does not run for it and the bit would otherwise persist. */
        ctn->sie_spared = 0;

        ngx_http_cache_turbo_lru_link_head(z, ctn);

        if (out_ctn != NULL) {
            *out_ctn = ctn;
        }

        return NGX_OK;
    }

    /* New entry.
     *
     * P4-1b: the admission decision, and the ONLY place in this module that
     * can refuse a storable response on frequency grounds. It sits here --
     * new-entry path only, before alloc_evict() -- for two reasons. (1) The
     * refresh path above updates an entry that is ALREADY resident and
     * displaces nobody; refusing there would evict-by-omission, which is a
     * different policy nobody asked for. (2) Being strictly before
     * alloc_evict() is what makes the termination argument in shm_admit()
     * hold: a refusal removes an alloc_evict() call, it never adds an
     * iteration to one.
     *
     * NGX_DECLINED, not NGX_ERROR: this is a policy answer, not a failure.
     * The store-declined path is already what a store_if() predicate refusal
     * returns, so callers handle it. */
    if (!ngx_http_cache_turbo_shm_admit(z, hash)) {
        return NGX_DECLINED;
    }

    ctn = ngx_http_cache_turbo_shm_alloc_evict(z,
              sizeof(ngx_http_cache_turbo_node_t));
    if (ctn == NULL) {
        return NGX_ERROR;
    }

    body = ngx_http_cache_turbo_blob_alloc(z, len);
    if (body == NULL) {
        ngx_http_cache_turbo_shm_free_locked(z, ctn,
            sizeof(ngx_http_cache_turbo_node_t));
        return NGX_ERROR;
    }

    ngx_memcpy(body, data, len);

    ctn->node.key = ngx_http_cache_turbo_shm_key64(key_hash);
    ngx_memcpy(ctn->key, key_hash, 32);
    ctn->kind = NGX_HTTP_CACHE_TURBO_NODE_ENTRY;
    ctn->data = body;
    ctn->len = len;
    ctn->fresh_until = now + fresh_ttl;
    ctn->stale_until = stale_ttl ? now + stale_ttl : 0;
    ctn->refreshing = 0;
    ctn->refresh_lock_until = 0;
    ctn->refresh_owner = 0;      /* CTXRDR-ADOPT-LEASE: no lease on a new ENTRY */
    ctn->miss_count = 0;
    ctn->l2_neg_until = 0;       /* L13: no memo on an ENTRY */
    ctn->last_access = now;      /* P1: fresh at LRU head */
    ctn->promotable = 0;         /* S8: unproven; second touch promotes */
    ctn->hash_crc32 = hash;      /* PERF-AUD2-10: save the recompute */
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    /* PERF-AUD2-10 invariant check: the documented contract (struct
     * field comment above, shm_admit() comment) is that `hash` equals
     * ngx_crc32_short(key_hash, 32) for this node's own key. Bounded
     * blast radius, not a correctness bug -- shm_lookup() discards its
     * `hash` parameter and descends on the widened key64 instead, so a
     * mismatch here can never mis-route a lookup or cross-serve
     * another key's object; the only consequence is shm_admit()
     * consulting the wrong W-TinyLFU sketch rows for this node as a
     * future eviction victim, degrading admission accuracy. Same
     * TEST_FAULTS diagnostic-counter convention as
     * breaker_wedge_observed (O4.4-i/H-2). */
    if (ngx_crc32_short(key_hash, 32) != hash) {
        (void) ngx_atomic_fetch_add(
            &ngx_http_cache_turbo_zone_sh(z)->test_hash_crc32_mismatch, 1);
    }
#endif

    ngx_rbtree_insert(&ngx_http_cache_turbo_zone_sh(z)->rbtree, &ctn->node);
    /* S8: every new node enters PROBATION (see lru_insert_new). */
    ngx_http_cache_turbo_lru_insert_new(z, ctn);

    if (out_ctn != NULL) {
        *out_ctn = ctn;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_cache_turbo_shm_store(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, u_char *data, size_t len,
    time_t fresh_ttl, time_t stale_ttl)
{
    ngx_int_t  rc;

    ngx_shmtx_lock(ngx_http_cache_turbo_zone_mutex(z));
    rc = ngx_http_cache_turbo_shm_store_locked(z, key_hash, hash, data, len,
                                                fresh_ttl, stale_ttl, NULL,
                                                NULL);
    ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));

    return rc;
}


/* C3: marker store. Same wire contract as _shm_store() above, plus the
 * `markers` presence-counter bookkeeping, all under ONE lock/unlock pair so
 * the "was this key already a marker" read, the write itself, and the
 * conditional increment are atomic with respect to every other zone-mutex
 * holder -- in particular ngx_http_cache_turbo_shm_evict_one(), which could
 * otherwise reclaim this exact node (decrementing `markers`) in the window
 * between a separate pre-check and a separate post-check, leaving the counter
 * one short of the node store_locked() goes on to (re)create.
 *
 * `was_marker` is read from `ctn->kind` BEFORE the store, not from any
 * property that survives it: store_locked()'s refresh branch unconditionally
 * resets kind to NGX_HTTP_CACHE_TURBO_NODE_ENTRY (it has no notion of a
 * marker), so kind cannot double as its own "already counted" signal across
 * the call the way it can for a plain read. Retagging to MARKER after every
 * single call (new-entry AND refresh alike) is what keeps kind accurate for
 * the NEXT free site's decrement check, no matter how many refreshes happen
 * in between -- markers are refreshed on every variant store (see
 * ngx_http_cache_turbo_marker_store()'s own comment), so that is the common
 * case, not the exception. */
ngx_int_t
ngx_http_cache_turbo_shm_store_marker(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, u_char *data, size_t len,
    time_t fresh_ttl, time_t stale_ttl)
{
    ngx_int_t                     rc;
    ngx_uint_t                    was_marker;
    ngx_http_cache_turbo_node_t  *ctn;
    ngx_http_cache_turbo_node_t  *written;

    ngx_shmtx_lock(ngx_http_cache_turbo_zone_mutex(z));

    ctn = ngx_http_cache_turbo_shm_lookup(z, key_hash, hash);
    was_marker = (ctn != NULL
                  && ctn->kind == NGX_HTTP_CACHE_TURBO_NODE_MARKER);

    /* PERF-AUD2-09: pass this same lookup straight into store_locked() (its
     * refresh path reuses the identical node, its new-entry path ignores a
     * non-NULL `ctn` argument since `ctn` here is NULL on that path anyway --
     * see store_locked()'s own comment) and take back a pointer to whatever
     * node it wrote via `written`, closing the second rbtree descent that
     * used to sit here as a THIRD post-store lookup for the exact key this
     * function already resolved (or is about to create) under the same
     * lock hold. */
    rc = ngx_http_cache_turbo_shm_store_locked(z, key_hash, hash, data, len,
                                                fresh_ttl, stale_ttl, ctn,
                                                &written);

    if (rc == NGX_OK) {
        ctn = written;

        if (ctn != NULL) {
            ctn->kind = NGX_HTTP_CACHE_TURBO_NODE_MARKER;

            if (!was_marker) {
                (void) ngx_atomic_fetch_add(
                    &ngx_http_cache_turbo_zone_sh(z)->markers, 1);
            }
        }
    }

    ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));

    return rc;
}


/* AUD-L2-PROMOTE-RACE / AUD-5XX-CTA: decide-then-write, one lock acquisition.
 * See the L1 vtable `store_if` comment in the header for the return contract
 * and the exact refusal rule each predicate applies. `now` is taken ONCE
 * inside the lock so the decision and the write see the same clock reading. */
ngx_int_t
ngx_http_cache_turbo_shm_store_if(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, u_char *data, size_t len,
    time_t fresh_ttl, time_t stale_ttl, ngx_uint_t predicate)
{
    time_t                        now;
    ngx_int_t                     rc;
    ngx_uint_t                    refuse;
    ngx_http_cache_turbo_node_t  *ctn;

    ngx_shmtx_lock(ngx_http_cache_turbo_zone_mutex(z));

    now = ngx_time();
    ctn = ngx_http_cache_turbo_shm_lookup(z, key_hash, hash);
    refuse = 0;

    if (ctn != NULL
        && ctn->kind == NGX_HTTP_CACHE_TURBO_NODE_ENTRY
        && ctn->len > 0)
    {
        switch (predicate) {

        case NGX_HTTP_CACHE_TURBO_STORE_IF_NEWER:
            /* Refuse iff the resident entry is strictly fresher than the
             * blob we are about to promote -- a slow L2 reply must never
             * displace a newer origin response that landed while it was
             * parked. */
            if (ctn->fresh_until > now + fresh_ttl) {
                refuse = 1;
            }
            break;

        case NGX_HTTP_CACHE_TURBO_STORE_IF_ABSENT_OR_DEAD:
            /* Exactly today's "protect" predicate, moved inside the lock:
             * refuse iff the resident entry is still within its stale
             * window. stale_until == 0 means FOREVER, not expired. */
            if (ctn->stale_until == 0 || now < ctn->stale_until) {
                refuse = 1;
            }
            break;

        default:
            /* Fail CLOSED. This is a guard API: an unrecognised predicate is
             * a programming error, and the safe answer to "may I overwrite
             * this entry?" from a rule nobody implemented is no. Falling
             * through with refuse = 0 would make a forgotten `case` overwrite
             * live entries silently -- and since STORE_IF_NEWER is 0, an
             * omitted argument would land on a real predicate rather than an
             * obviously invalid one. */
            refuse = 1;
            break;
        }
    }

    if (refuse) {
        ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));
        return NGX_DECLINED;
    }

    /* PERF-AUD2-09: reuse this function's own predicate-check lookup instead
     * of store_locked() repeating the rbtree descent for the same key under
     * the same lock hold. */
    rc = ngx_http_cache_turbo_shm_store_locked(z, key_hash, hash, data, len,
                                                fresh_ttl, stale_ttl, ctn,
                                                NULL);
    ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));

    return rc;
}


/* P5-4: 304 freshening. A revalidation (client-conditional main request or
 * SWR background refresh) came back 304 Not Modified -- the origin's own
 * confirmation that the stored body is still correct. status_ttl() refuses
 * 304 unconditionally (conf.c: cache_turbo_valid rejects it at config time,
 * so it can never appear in valid_status; status_ttl() returns -1), which is
 * deliberate for the ordinary capture path -- a 304 has no body and must
 * never be STORED as if it were a representation. But that left no way to
 * extend an existing entry's life from a 304 either, so the entry just aged
 * out and the next request paid a full blocking regeneration -- exactly
 * what the swr-validators probe (PR #350) demonstrates.
 *
 * This is NOT store(): no allocation, no LRU re-segmentation, no touching
 * ctn->data. It bumps ONLY the freshness window on the resident node, in
 * place, under the SAME zone mutex every other node-field mutation in this
 * file uses (store_locked above, blob_acquire/release, the SWR claim/lease
 * fields) -- there is exactly one lock protecting node metadata in this
 * module and this reuses it rather than inventing a second protocol. A
 * concurrent reader takes the identical lock before it can observe
 * fresh_until/stale_until (the L1 access-prologue site in access.c holds
 * z->shpool->mutex across its lookup + snapshot), so it either sees the pair
 * entirely before this write or entirely after -- never torn.
 *
 * Refuses (NGX_DECLINED) when there is nothing to freshen: no resident
 * entry, a stub/counter node (kind != ENTRY), or an entry with no body
 * (len == 0) -- freshening a body that was never captured would fabricate a
 * lifetime for content this zone never actually held.
 *
 * Also clears refreshing/refresh_lock_until, same as a real store does
 * (shm_store_locked above): a 304 answers the outstanding revalidation just
 * as conclusively as a 200 would, and leaving the single-flight lease held
 * would wedge the SWR loop out of ever revalidating this key again until
 * the lease's own TTL expires. */
ngx_int_t
ngx_http_cache_turbo_shm_freshen(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, time_t fresh_ttl, time_t stale_ttl)
{
    time_t                        now;
    ngx_http_cache_turbo_node_t  *ctn;

    ngx_shmtx_lock(ngx_http_cache_turbo_zone_mutex(z));

    ctn = ngx_http_cache_turbo_shm_lookup(z, key_hash, hash);

    if (ctn == NULL
        || ctn->kind != NGX_HTTP_CACHE_TURBO_NODE_ENTRY
        || ctn->len == 0)
    {
        ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));
        return NGX_DECLINED;
    }

    now = ngx_time();

    ctn->fresh_until = now + fresh_ttl;
    ctn->stale_until = stale_ttl ? now + stale_ttl : 0;
    ctn->refreshing = 0;
    ctn->refresh_lock_until = 0;
    ctn->refresh_owner = 0;
    ctn->last_access = now;

    ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));

    return NGX_OK;
}


void
ngx_http_cache_turbo_shm_stats(ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_stats_t *out)
{
    ngx_atomic_uint_t  cnt;

    out->hits         = ngx_http_cache_turbo_zone_sh(z)->hits;
    out->misses       = ngx_http_cache_turbo_zone_sh(z)->misses;
    out->stale_serves = ngx_http_cache_turbo_zone_sh(z)->stale_serves;
    out->refreshes    = ngx_http_cache_turbo_zone_sh(z)->refreshes;
    out->evictions    = ngx_http_cache_turbo_zone_sh(z)->evictions;
    out->l2_hits      = ngx_http_cache_turbo_zone_sh(z)->l2_hits;
    out->l2_misses    = ngx_http_cache_turbo_zone_sh(z)->l2_misses;
    out->lock_waits   = ngx_http_cache_turbo_zone_sh(z)->lock_waits;
    out->min_uses_skips = ngx_http_cache_turbo_zone_sh(z)->min_uses_skips;
    out->l2_neg_skips = ngx_http_cache_turbo_zone_sh(z)->l2_neg_skips;
    out->bypasses     = ngx_http_cache_turbo_zone_sh(z)->bypasses;

    out->refuse_set_cookie    = ngx_http_cache_turbo_zone_sh(z)->refuse_set_cookie;
    out->refuse_encoded       = ngx_http_cache_turbo_zone_sh(z)->refuse_encoded;
    out->refuse_vary_unsafe   = ngx_http_cache_turbo_zone_sh(z)->refuse_vary_unsafe;
    out->refuse_authorization = ngx_http_cache_turbo_zone_sh(z)->refuse_authorization;
    out->refuse_cache_control = ngx_http_cache_turbo_zone_sh(z)->refuse_cache_control;
    out->refuse_require_header = ngx_http_cache_turbo_zone_sh(z)->refuse_require_header;
    out->refuse_partial       = ngx_http_cache_turbo_zone_sh(z)->refuse_partial;
    out->refuse_head          = ngx_http_cache_turbo_zone_sh(z)->refuse_head;

    /* Autotune introspection (v4-3): average origin-regen cost and the live beta
     * verdict, so the admin GET can render the tuning without an internal probe. */
    cnt = ngx_http_cache_turbo_zone_sh(z)->cost_count;
    out->cost_ms        = cnt ? (ngx_http_cache_turbo_zone_sh(z)->cost_sum_ms / cnt) : 0;
    out->autotuned_beta = ngx_http_cache_turbo_zone_sh(z)->autotuned_beta;
    out->autotuned_load = ngx_http_cache_turbo_zone_sh(z)->autotuned_load;   /* v4-4 load factor ×1000 */

    /* P6/O4.1 breaker introspection. Read raw -- do NOT call breaker_state()
     * here: that function performs the OPEN -> HALF_OPEN transition, and an
     * admin GET must observe the breaker, never drive it. */
    out->breaker_state = ngx_http_cache_turbo_zone_sh(z)->breaker_state;
    out->breaker_opens = ngx_http_cache_turbo_zone_sh(z)->breaker_opens;

    /* S7.1: production serve/failure counters. Plain reads, same as every
     * other counter above -- these are simple lifetime tallies, not the
     * breaker's transitioning state. */
    out->sie_serves      = ngx_http_cache_turbo_zone_sh(z)->sie_serves;
    out->breaker_serves  = ngx_http_cache_turbo_zone_sh(z)->breaker_serves;
    out->origin_failures = ngx_http_cache_turbo_zone_sh(z)->origin_failures;

    /* COR-5(b)/L9: store-time index-drop counters. Plain reads, same as
     * every other lifetime tally above. */
    out->varidx_drops     = ngx_http_cache_turbo_zone_sh(z)->varidx_drops;
    out->tag_index_drops  = ngx_http_cache_turbo_zone_sh(z)->tag_index_drops;
    out->tag_cap_drops    = ngx_http_cache_turbo_zone_sh(z)->tag_cap_drops;

    /* P3-7: live gauge, not a lifetime tally -- read the same as every other
     * counter here (plain, unlocked; the atomic itself is the sync point). */
    out->bg_inflight = ngx_http_cache_turbo_zone_sh(z)->bg_inflight;

    /* P4-1b: admission introspection. Plain reads under no lock, exactly like
     * every counter above -- these are diagnostics, not a decision input. */
    out->sketch_gen        = (ngx_atomic_uint_t) ngx_http_cache_turbo_zone_sh(z)->sketch_gen;
    out->sketch_bumps      = (ngx_atomic_uint_t) ngx_http_cache_turbo_zone_sh(z)->sketch_bumps;
    out->admission_refused = (ngx_atomic_uint_t) ngx_http_cache_turbo_zone_sh(z)->admission_refused;

    /* P4-2-s3a: live used-bytes gauge (cached payload+metadata charged by
     * shm_alloc_evict / discharged by shm_free_locked). Plain read like the
     * sketch fields above -- diagnostics, not a decision input. */
    out->used_bytes = (ngx_atomic_uint_t) ngx_http_cache_turbo_zone_sh(z)->used_bytes;
    out->markers    = ngx_http_cache_turbo_zone_sh(z)->markers;
}


/* Forward declaration: resolve_miss() (below) needs this before its
 * definition further down the file. */
static ngx_int_t
ngx_http_cache_turbo_shm_count_miss_locked(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, ngx_int_t min_uses, time_t min_uses_window,
    ngx_http_cache_turbo_node_t *ctn, time_t now);


/* Cold-miss single-flight claim (v10), LOCK-HELD core. Operates on a `ctn`
 * the caller already resolved via shm_lookup() under the SAME mutex hold --
 * factored out for S231-PERF-MISSLOCKS so resolve_miss() below can share one
 * lookup/lock between this and count_miss() instead of each doing its own.
 * `ctn` may be NULL (key absent), matching the original single-call version.
 *
 * On CLAIM_FRESH the raced-in entry's blob pointer/len are handed back via
 * *fresh_data / *fresh_len, and the PERF-7 refcount is acquired RIGHT HERE,
 * still inside this function's critical section (the caller holds the lock
 * across this whole call -- see resolve_miss() below). This is load-bearing,
 * not an optimisation: ngx_http_cache_turbo_blob_acquire()'s own contract
 * (module.h) requires it be called "with shpool->mutex held (same critical
 * section as the lookup that produced `data`)" -- pinning the refcount is
 * what makes the pointer safe to dereference AFTER the caller unlocks. An
 * earlier version of this merge returned the raw pointer and left the
 * caller to acquire() after unlocking, which is a use-after-free: another
 * worker can evict the entry and drop the last reference in the gap between
 * the unlock and the caller's acquire(), so acquire() then increments a
 * refcount inside already-freed slab memory and the caller's serve() reads
 * a freed body.
 *
 * *fresh_data is non-NULL if and only if the caller now OWNS a reference
 * that MUST be released on every path that does not hand it to serve()
 * (serve() takes ownership of exactly one reference via its own cleanup
 * registration). A standalone caller that does not want the blob at all
 * (there is none today) may pass NULL for `fresh_data` and this function
 * skips the acquire() entirely -- no reference is taken, so there is
 * nothing for that caller to release.
 *
 * Every read/mutate/return here is byte-for-byte the original claim() body,
 * plus this one acquire() call -- only the lock and the lookup moved to the
 * caller. */
static ngx_int_t
ngx_http_cache_turbo_shm_claim_locked(ngx_http_cache_turbo_zone_t *z,
    uint32_t hash, u_char *key_hash, time_t lock_ttl, uint64_t *owner,
    ngx_http_cache_turbo_node_t *ctn, time_t now,
    u_char **fresh_data, size_t *fresh_len)
{
    /* CTXRDR-ADOPT-LEASE: no lease unless we actually win one below. Cleared up
     * front so every early return is a non-owner return by construction. */
    *owner = 0;

    if (ctn != NULL) {
        /* A real fresh entry raced in while we were on the cold path: re-serve
         * it, do NOT regenerate. */
        if (ctn->len > 0 && now < ctn->fresh_until) {
            if (fresh_data != NULL) {
                /* Acquire the PERF-7 refcount HERE, still under the caller's
                 * lock -- see the function comment above for why this may
                 * not move to the caller after unlock. The caller now owns
                 * this reference and must release it on any path that does
                 * not hand *fresh_data to serve(). */
                ngx_http_cache_turbo_blob_acquire(ctn->data);
                *fresh_data = ctn->data;
            }
            if (fresh_len != NULL) {
                *fresh_len = ctn->len;
            }
            return NGX_HTTP_CACHE_TURBO_CLAIM_FRESH;
        }

        /* Someone is already regenerating and the lock has not expired: wait. */
        if (ctn->refreshing && now < ctn->refresh_lock_until) {
            return NGX_HTTP_CACHE_TURBO_CLAIM_LOSER;
        }

        /* Expired entry or a dead in-flight stub (the previous winner died):
         * take it over as the new single regenerator. Any stale data left in
         * place is past its stale window so no one serves it; the winner
         * overwrites it on store().
         *
         * ⚠ The node's KIND is deliberately left alone. An expired ENTRY keeps its
         * (past-stale, unservable) blob until store() replaces it -- that is the
         * pre-existing contract and the blob's lifetime is not this fix's business.
         * `refreshing` alone marks the single-flight; for a COUNTER that is
         * precisely what makes it a stub.
         *
         * ⚠ l2_neg_until is deliberately NOT cleared. A COUNTER may carry a live
         * memo armed moments ago by l2_neg_set() on THIS request; clearing it here
         * destroyed the memo before any later request could read it, collapsing
         * the window to ~1 request (CodeRabbit CR-A on PR #77). The memo describes
         * L2's contents, which a local single-flight does not change, so it
         * legitimately outlives the regen. unstub() no longer depends on this
         * reset -- it identifies a stub by kind + refreshing, not by shape. */
        ctn->refreshing = 1;
        ctn->refresh_lock_until = now + lock_ttl;
        /* CTXRDR-ADOPT-LEASE: a NEW lease, even though the node already carried
         * one. This is precisely the rollover the token exists for -- the
         * previous holder's token is now stale, so its unstub() and any adoption
         * it attempts will (correctly) no longer match. */
        ctn->refresh_owner = ++ngx_http_cache_turbo_zone_sh(z)->owner_seq;
        *owner = ctn->refresh_owner;
        return NGX_HTTP_CACHE_TURBO_CLAIM_WINNER;
    }

    /* No node at all: create a stub (data == NULL, len == 0) marking the key as
     * in flight so concurrent first-hits wait instead of stampeding the origin.
     * The winner's store() finds it via lookup and overwrites it into a real
     * node (clearing refreshing). LRU eviction may reclaim a stub under memory
     * pressure — harmless, it just costs an extra origin hit. */
    ctn = ngx_http_cache_turbo_shm_alloc_evict(z,
              sizeof(ngx_http_cache_turbo_node_t));
    if (ctn == NULL) {
        /* Out of slab: cannot mark the key in flight, so just regenerate
         * (winner, no single-flight this time — correct, only less efficient).
         * CTXRDR-ADOPT-LEASE: *owner stays 0 deliberately. There is no node and
         * therefore no lease, so this winner must never later clear anyone's --
         * a 0 token matches nothing in unstub()/owns(). */
        return NGX_HTTP_CACHE_TURBO_CLAIM_WINNER;
    }

    ctn->node.key = ngx_http_cache_turbo_shm_key64(key_hash);
    ngx_memcpy(ctn->key, key_hash, 32);
    ctn->kind = NGX_HTTP_CACHE_TURBO_NODE_COUNTER;  /* + refreshing = a stub */
    ctn->data = NULL;
    ctn->len = 0;
    ctn->fresh_until = 0;
    ctn->stale_until = 0;
    ctn->refreshing = 1;
    ctn->refresh_lock_until = now + lock_ttl;
    ctn->refresh_owner = ++ngx_http_cache_turbo_zone_sh(z)->owner_seq;   /* CTXRDR-ADOPT-LEASE */
    ctn->miss_count = 0;
    ctn->l2_neg_until = 0;       /* brand-new node: no memo to preserve */
    ctn->last_access = now;      /* P1: init the coarse LRU stamp */
    ctn->promotable = 0;         /* S8: unproven; second touch promotes */
    ctn->hash_crc32 = hash;      /* PERF-AUD2-10: save the recompute */
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    /* PERF-AUD2-10 invariant check: the documented contract (struct
     * field comment above, shm_admit() comment) is that `hash` equals
     * ngx_crc32_short(key_hash, 32) for this node's own key. Bounded
     * blast radius, not a correctness bug -- shm_lookup() discards its
     * `hash` parameter and descends on the widened key64 instead, so a
     * mismatch here can never mis-route a lookup or cross-serve
     * another key's object; the only consequence is shm_admit()
     * consulting the wrong W-TinyLFU sketch rows for this node as a
     * future eviction victim, degrading admission accuracy. Same
     * TEST_FAULTS diagnostic-counter convention as
     * breaker_wedge_observed (O4.4-i/H-2). */
    if (ngx_crc32_short(key_hash, 32) != hash) {
        (void) ngx_atomic_fetch_add(
            &ngx_http_cache_turbo_zone_sh(z)->test_hash_crc32_mismatch, 1);
    }
#endif

    ngx_rbtree_insert(&ngx_http_cache_turbo_zone_sh(z)->rbtree, &ctn->node);
    /* S8: every new node enters PROBATION (see lru_insert_new). */
    ngx_http_cache_turbo_lru_insert_new(z, ctn);

    *owner = ctn->refresh_owner;

    return NGX_HTTP_CACHE_TURBO_CLAIM_WINNER;
}


/* Cold-miss single-flight claim (v10), public single-call form. See the L1
 * vtable `claim` comment in the header. Thin lock+lookup wrapper around the
 * _locked core above -- unchanged behaviour, still one lock/one lookup per
 * call when used standalone (the min_uses<=1 case, where there is no
 * count_miss() to merge with). */
ngx_int_t
ngx_http_cache_turbo_shm_claim(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, time_t lock_ttl, uint64_t *owner)
{
    ngx_int_t                     rc;
    time_t                        now;
    ngx_http_cache_turbo_node_t  *ctn;

    now = ngx_time();

    ngx_shmtx_lock(ngx_http_cache_turbo_zone_mutex(z));
    ctn = ngx_http_cache_turbo_shm_lookup(z, key_hash, hash);
    rc = ngx_http_cache_turbo_shm_claim_locked(z, hash, key_hash, lock_ttl,
             owner, ctn, now, NULL, NULL);
    ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));

    return rc;
}


/* S231-PERF-MISSLOCKS: merged cold-miss resolution. A cold miss with
 * min_uses > 1 and cache_turbo_lock on used to take the zone mutex twice and
 * descend the rbtree twice for the SAME key on the SAME request pass --
 * count_miss() followed immediately by claim(), with no park/I-O between
 * them (see module.c's access handler: count_miss only runs when
 * `!ctx->lock_done`, i.e. strictly before claim() fires on that same call).
 * This does one lock/one lookup and runs both cores against the shared `ctn`.
 *
 * Contract: identical to calling count_miss() then, only if it returned
 * NGX_OK, claim() -- in that order, both under what is now a single
 * critical section instead of two:
 *
 *   - count_miss_rc receives exactly what standalone count_miss() would have
 *     returned (NGX_OK / NGX_DECLINED). Its mutation (miss_count++, or a new
 *     counter node) happens exactly once, identically to the standalone call.
 *   - If count_miss_rc is NGX_DECLINED, claim() is NOT invoked (matching the
 *     caller's own `if (... == NGX_DECLINED) return` short-circuit in
 *     module.c -- claim() never ran in that case before either) and the
 *     return value is CLAIM_WINNER/LOSER/FRESH's caller must not consult;
 *     the function returns NGX_HTTP_CACHE_TURBO_CLAIM_WINNER as a dummy that
 *     the caller ignores (mirrors "no claim attempted").
 *   - If count_miss_rc is NGX_OK, claim_locked() runs against the SAME ctn
 *     (re-fetched from the rbtree only once, at the top) with the SAME `now`,
 *     producing exactly the CLAIM_WINNER/LOSER/FRESH / *owner claim() would
 *     have returned had it been called separately right after -- the two
 *     mutations (count_miss's counter bump / node creation, then claim's
 *     refreshing/owner stamp or stub creation) apply in the same order, to
 *     the same node, under the same lock hold count_miss() and claim() used
 *     to take separately.
 *   - On CLAIM_FRESH, *fresh_data / *fresh_len are populated exactly as
 *     claim_locked() documents above -- INCLUDING that claim_locked() has
 *     already called blob_acquire() on *fresh_data before this function
 *     unlocks. The caller receives an already-referenced pointer, not a
 *     bare one to acquire later: nothing may read ctn->data and defer the
 *     acquire() past this function's unlock, because the mutex is the only
 *     thing stopping a concurrent evict from freeing that blob out from
 *     under an unreferenced pointer. The caller owns that one reference and
 *     must release it (ngx_http_cache_turbo_blob_release()) on every path
 *     that does not hand it to ngx_http_cache_turbo_serve() -- serve()'s
 *     cleanup registration is what eventually drops it on the pool-lifetime
 *     path, so a caller that decides NOT to serve (e.g. RFC-1 req_reval)
 *     must release it explicitly or leak the reference.
 *
 * LOCKING WINDOW, pointer by pointer -- everything resolve_miss() hands back
 * across its own unlock:
 *   - *owner (a uint64_t token, not a pointer): safe by value, no lifetime
 *     issue. Its liveness as a lease is re-checked later via shm_owns(),
 *     never assumed from having once been returned here.
 *   - *count_miss_rc (an ngx_int_t verdict): safe by value.
 *   - *fresh_data / *fresh_len: *fresh_data is safe ACROSS the unlock
 *     specifically because claim_locked() already pinned it with
 *     blob_acquire() before returning -- the refcount, not the mutex, is
 *     what keeps the blob alive from here on. *fresh_len is a snapshot
 *     size_t copied from ctn->len while the lock was held; it describes the
 *     referenced blob's length at accept time and does not need its own
 *     protection once the reference exists.
 *
 * l2_neg_check is deliberately NOT folded in here: on the request path it
 * runs before this call and can be followed by an async L2 GET
 * (clcf->backend->get() park/resume) before count_miss/claim ever run, so
 * its own lock/lookup is not always adjacent to these two -- merging it would
 * either force it onto the wrong side of a potential async park (widening
 * the critical section across a redis round-trip: never acceptable) or
 * require plumbing an "was there a park" flag through the whole request
 * struct for a case (no L2 backend, or an already-resolved L2) that is not
 * always true. count_miss and claim, by contrast, are ALWAYS adjacent on the
 * first pass with no possible park between them (see module.c), so only
 * those two merge here. */
ngx_int_t
ngx_http_cache_turbo_shm_resolve_miss(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, ngx_int_t min_uses, time_t min_uses_window,
    time_t lock_ttl, uint64_t *owner, ngx_int_t *count_miss_rc,
    u_char **fresh_data, size_t *fresh_len)
{
    ngx_int_t                     rc;
    time_t                        now;
    ngx_http_cache_turbo_node_t  *ctn;

    now = ngx_time();
    *owner = 0;

    ngx_shmtx_lock(ngx_http_cache_turbo_zone_mutex(z));

    ctn = ngx_http_cache_turbo_shm_lookup(z, key_hash, hash);

    *count_miss_rc = ngx_http_cache_turbo_shm_count_miss_locked(z, key_hash,
                          hash, min_uses, min_uses_window, ctn, now);

    if (*count_miss_rc == NGX_DECLINED) {
        /* Matches the standalone caller's own short-circuit: claim() never
         * ran when count_miss() declined. Nothing further to report. */
        ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));
        return NGX_HTTP_CACHE_TURBO_CLAIM_WINNER;   /* caller must not use this */
    }

    /* count_miss_locked() may have just allocated the counter node (key was
     * absent). Re-resolve so claim_locked() sees it instead of racing its own
     * "no node" branch and allocating a SECOND node for the same key -- this
     * is the one behavioural seam the merge must close: the two-call version
     * had claim() do its own fresh lookup after count_miss()'s unlock, which
     * naturally picked up whatever count_miss() had just inserted. */
    if (ctn == NULL) {
        ctn = ngx_http_cache_turbo_shm_lookup(z, key_hash, hash);
    }

    rc = ngx_http_cache_turbo_shm_claim_locked(z, hash, key_hash, lock_ttl,
             owner, ctn, now, fresh_data, fresh_len);

    ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));

    return rc;
}


/* CTXRDR-ADOPT-LEASE: is `owner` still the live lease holder for this key?
 * See the header for why request-local state cannot answer this. */
ngx_int_t
ngx_http_cache_turbo_shm_owns(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, uint64_t owner)
{
    ngx_int_t                     rc;
    ngx_http_cache_turbo_node_t  *ctn;

    /* 0 is never a live token (owner_seq starts at 1), so an unclaimed or
     * already-released ctx is rejected without touching the zone. */
    if (owner == 0) {
        return NGX_DECLINED;
    }

    ngx_shmtx_lock(ngx_http_cache_turbo_zone_mutex(z));

    ctn = ngx_http_cache_turbo_shm_lookup(z, key_hash, hash);

    /* Identity AND liveness. `refreshing` alone would accept a node whose lease
     * we still nominally stamp but that store()/unstub() has already resolved;
     * the token alone would accept a resolved node that has not yet been reused.
     * A lease is ours only while both hold.
     *
     * ⚠ Deliberately NOT tested: refresh_lock_until. An expired deadline does not
     * end the lease -- it only makes the node ELIGIBLE for takeover by the next
     * claim(). Until that takeover actually happens, refresh_owner still names
     * us and we are still the single regenerator. Rejecting on the deadline here
     * would send a request that legitimately owns the stub back into cold_wait()
     * to park on its own lease, which is the original CTXRDR defect. */
    rc = (ctn != NULL
          && ctn->refreshing
          && ctn->refresh_owner == owner)
         ? NGX_OK : NGX_DECLINED;

    ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));

    return rc;
}


/* Remove a leftover cold-miss stub (v10). Only acts if the node is still a stub
 * (data == NULL / len == 0) — a real entry stored in the meantime is left
 * intact. Called when a cold-miss winner's response was non-cacheable so the
 * in-flight marker would otherwise block waiters until refresh_lock_until. */
void
ngx_http_cache_turbo_shm_unstub(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, uint64_t owner)
{
    ngx_http_cache_turbo_node_t  *ctn;

    /* CTXRDR-ADOPT-LEASE: never held a lease, or already released it. Nothing to
     * clear, and matching on the flags alone here is exactly how a stale caller
     * used to free the CURRENT winner's lease. */
    if (owner == 0) {
        return;
    }

    ngx_shmtx_lock(ngx_http_cache_turbo_zone_mutex(z));

    ctn = ngx_http_cache_turbo_shm_lookup(z, key_hash, hash);

    /* Two separate jobs, and conflating them is what made this function a bug
     * factory:
     *
     *   1. ALWAYS clear the single-flight on a claimed COUNTER. That is what
     *      unblocks waiters, and it must happen whatever else the node carries.
     *   2. Free the node only if it then carries NOTHING worth keeping.
     *
     * ⚠ Do NOT gate step 1 on what the node carries. A previous version required
     * `l2_neg_until <= now`, so a node holding a LIVE memo kept its `refreshing`
     * flag after its winner's response turned out non-cacheable -- every later
     * request for that key then parked on a stub nobody would ever fill, until
     * refresh_lock_until expired. That is a hang, not a slowdown: measured
     * 2026-07-19, it timed out the runtime suite outright.
     *
     * ⚠ Do NOT reduce the free test to a shape check (`len == 0 && data == NULL`).
     * That shape is shared by the stub, the min_uses counter and the L13 memo --
     * the overloading that produced this whole defect class. When only
     * l2_neg_until guarded it, a counter node mid-count was freed outright and its
     * min_uses progress silently reset (CR-B); the in-tree justification for that
     * ("the suite logs miss_count == 0 on all 68 calls") was measured under
     * min_uses 4, a config where counters never reach here at all. Evidence of
     * absence, mistaken for absence of the path.
     *
     * An ENTRY is never touched: it holds a body someone may still serve.
     *
     * ⚠ CTXRDR-ADOPT-LEASE: the owner test is NOT a fourth shape check to be
     * folded into the ones above -- it is an identity check, and it is what makes
     * step (1) safe to keep unconditional. claim() re-leases an expired stub to a
     * new winner, so a slow LOSER reaching here later would otherwise satisfy
     * kind + refreshing against the NEW holder's lease and clear it, freeing
     * every waiter to stampede the origin. Mismatch => someone else's lease, and
     * the only correct action is to leave the node completely alone. */
    if (ctn != NULL
        && ctn->kind == NGX_HTTP_CACHE_TURBO_NODE_COUNTER
        && ctn->refreshing
        && ctn->refresh_owner == owner)
    {
        /* (1) release the single-flight -- unconditional, once it is OURS */
        ctn->refreshing = 0;
        ctn->refresh_lock_until = 0;
        ctn->refresh_owner = 0;

        /* (2) reclaim only if nothing else lives on this node: no min_uses
         * progress and no live negative memo. Either one means the node still
         * carries state the caller never asked to discard, so it stays as a plain
         * COUNTER and expires on its own terms. */
        if (ctn->miss_count == 0 && ctn->l2_neg_until <= ngx_time()) {
            ngx_http_cache_turbo_lru_unlink(z, ctn);
            ngx_http_cache_turbo_zone_sh(z)->n_entries--;
            ngx_rbtree_delete(&ngx_http_cache_turbo_zone_sh(z)->rbtree, &ctn->node);
            ngx_http_cache_turbo_shm_free_locked(z, ctn,
                sizeof(ngx_http_cache_turbo_node_t));
        }
    }

    ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));
}


/* min_uses miss counter (v15), LOCK-HELD core. Operates on a `ctn` the caller
 * already resolved via shm_lookup() under the SAME mutex hold -- factored out
 * so S231-PERF-MISSLOCKS can share one lookup/lock between this and claim()
 * instead of each doing its own. `ctn` may be NULL (key absent); on a NULL
 * `ctn` this allocates the counter node exactly as the original single-call
 * version did. Every read/mutate/return here is byte-for-byte the original
 * count_miss body -- only the lock and the lookup moved to the caller.
 *
 * P3-6: min_uses_window enables windowed miss_count resets. When a counter node
 * is accessed for a miss, if now - last_access > window, reset miss_count to 0
 * before incrementing (treating this as a fresh miscount cycle). 0 = OFF
 * (lifetime counter, v15 behavior). */
static ngx_int_t
ngx_http_cache_turbo_shm_count_miss_locked(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, ngx_int_t min_uses, time_t min_uses_window,
    ngx_http_cache_turbo_node_t *ctn, time_t now)
{
    if (ctn != NULL) {
        /* A real entry (even expired/stale being refreshed) is already proven
         * cacheable — never re-gate it, and do not touch its counter. */
        if (ctn->kind == NGX_HTTP_CACHE_TURBO_NODE_ENTRY && ctn->len > 0) {
            return NGX_OK;
        }

        /* A live single-flight stub: another request already crossed the
         * threshold and is regenerating. Proceed so the caller's claim() makes
         * this request a waiter; don't count (this is not an un-coalesced miss). */
        if (ctn->refreshing && now < ctn->refresh_lock_until) {
            return NGX_OK;
        }

        /* A counter node (or a dead stub): this is a genuine cold miss for a key
         * not yet cached. Count it; cross the threshold => store-eligible.
         *
         * P3-6: apply windowing reset BEFORE incrementing. If min_uses_window > 0
         * and now - last_access > window, reset the counter as if it were a fresh
         * node. This uses last_access BEFORE updating it (which happens later
         * when the node is touched after claim()). */
        if (min_uses_window > 0 && (now - ctn->last_access) > min_uses_window) {
            ctn->miss_count = 0;
        }

        ctn->miss_count++;
        if ((ngx_int_t) ctn->miss_count >= min_uses) {
            return NGX_OK;
        }
        return NGX_DECLINED;
    }

    /* No node yet: create a counter node (data == NULL / len == 0 /
     * refreshing == 0) recording this first miss. It is invisible to the serve
     * branches (their len > 0 guards skip it) and converts into the cold-miss
     * winner's stub via claim() once the threshold is reached. LRU eviction may
     * reclaim a cold counter node — harmless, it just resets the count. */
    ctn = ngx_http_cache_turbo_shm_alloc_evict(z,
              sizeof(ngx_http_cache_turbo_node_t));
    if (ctn == NULL) {
        /* Out of slab: cannot track the count, so just let it cache now
         * (correct, only less selective than min_uses would like). */
        return NGX_OK;
    }

    ctn->node.key = ngx_http_cache_turbo_shm_key64(key_hash);
    ngx_memcpy(ctn->key, key_hash, 32);
    ctn->kind = NGX_HTTP_CACHE_TURBO_NODE_COUNTER;
    ctn->data = NULL;
    ctn->len = 0;
    ctn->fresh_until = 0;
    ctn->stale_until = 0;
    ctn->refreshing = 0;
    ctn->refresh_lock_until = 0;
    ctn->refresh_owner = 0;      /* CTXRDR-ADOPT-LEASE: a counter holds no lease */
    ctn->miss_count = 1;
    ctn->l2_neg_until = 0;       /* L13: no memo yet; l2_neg_set stamps it */
    ctn->last_access = now;      /* P1: init the coarse LRU stamp */
    ctn->promotable = 0;         /* S8: unproven; second touch promotes */
    ctn->hash_crc32 = hash;      /* PERF-AUD2-10: save the recompute */
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    /* PERF-AUD2-10 invariant check: the documented contract (struct
     * field comment above, shm_admit() comment) is that `hash` equals
     * ngx_crc32_short(key_hash, 32) for this node's own key. Bounded
     * blast radius, not a correctness bug -- shm_lookup() discards its
     * `hash` parameter and descends on the widened key64 instead, so a
     * mismatch here can never mis-route a lookup or cross-serve
     * another key's object; the only consequence is shm_admit()
     * consulting the wrong W-TinyLFU sketch rows for this node as a
     * future eviction victim, degrading admission accuracy. Same
     * TEST_FAULTS diagnostic-counter convention as
     * breaker_wedge_observed (O4.4-i/H-2). */
    if (ngx_crc32_short(key_hash, 32) != hash) {
        (void) ngx_atomic_fetch_add(
            &ngx_http_cache_turbo_zone_sh(z)->test_hash_crc32_mismatch, 1);
    }
#endif

    ngx_rbtree_insert(&ngx_http_cache_turbo_zone_sh(z)->rbtree, &ctn->node);
    /* S8: every new node enters PROBATION (see lru_insert_new). */
    ngx_http_cache_turbo_lru_insert_new(z, ctn);

    /* First miss: below threshold unless min_uses == 1 (caller guards that). */
    return (min_uses <= 1) ? NGX_OK : NGX_DECLINED;
}


/* min_uses miss counter (v15), public single-call form. See the L1 vtable
 * `count_miss` comment in the header. Only called when min_uses > 1. Thin
 * lock+lookup wrapper around the _locked core above -- unchanged behaviour,
 * still one lock/one lookup per call when used standalone (the min_uses>1 &&
 * cache_turbo_lock-off case, where there is no claim() to merge with).
 *
 * P3-6: min_uses_window enables windowed resets (see count_miss_locked). */
ngx_int_t
ngx_http_cache_turbo_shm_count_miss(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, ngx_int_t min_uses, time_t min_uses_window)
{
    ngx_int_t                     rc;
    time_t                        now;
    ngx_http_cache_turbo_node_t  *ctn;

    now = ngx_time();

    ngx_shmtx_lock(ngx_http_cache_turbo_zone_mutex(z));
    ctn = ngx_http_cache_turbo_shm_lookup(z, key_hash, hash);
    rc = ngx_http_cache_turbo_shm_count_miss_locked(z, key_hash, hash,
             min_uses, min_uses_window, ctn, now);
    ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));

    return rc;
}


/* L2 negative memo (L13). Is there a live "L2 missed this key recently" memo?
 * Returns NGX_DECLINED to SKIP the L2 GET, NGX_OK to consult L2 as usual.
 * See the L1 vtable `l2_neg_check` comment. Only called when
 * l2_negative_ttl > 0. */
ngx_int_t
ngx_http_cache_turbo_shm_l2_neg_check(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash)
{
    time_t                        now;
    ngx_int_t                     rc;
    ngx_http_cache_turbo_node_t  *ctn;

    now = ngx_time();
    rc = NGX_OK;

    ngx_shmtx_lock(ngx_http_cache_turbo_zone_mutex(z));

    ctn = ngx_http_cache_turbo_shm_lookup(z, key_hash, hash);

    /* Only a COUNTER can carry a memo, and only while it has not expired.
     *
     * ⚠ `refreshing` is deliberately NOT consulted. It used to be, and that is
     * what limited the memo to ~1 request: l2_neg_check runs BEFORE claim() in the
     * request path (module.c), so req1 armed the memo and req1's own claim() then
     * marked the very same node refreshing, masking the memo from req2 onward. At
     * the default min_uses 1 that made the whole feature a near no-op (Codex #4).
     *
     * Consulting it is also wrong on the merits: `refreshing` says a LOCAL regen
     * is in the air, which tells us nothing about whether L2 holds the key. The
     * memo is a statement about L2's contents; a local single-flight does not
     * change them. Skipping the L2 GET while a regen is in flight is exactly as
     * safe as skipping it otherwise -- the memo holds no body and can never cause
     * a stale serve. */
    if (ctn != NULL
        && ctn->kind == NGX_HTTP_CACHE_TURBO_NODE_COUNTER
        && ctn->l2_neg_until > now)
    {
        rc = NGX_DECLINED;

        /* P1/Codex #2: a consulted memo is in USE -- re-head it on the same 1s
         * granularity as a served ENTRY. Without this a memo node keeps the
         * last_access it was created with and sinks to the LRU tail no matter how
         * often it is read, making it a PREFERRED eviction victim ahead of colder
         * entries. Eviction of a memo is legitimate under real slab pressure (a
         * body is worth more than a memo, and losing one only costs an RTT), but
         * it should be evicted on its true recency. */
        /* S8: routed through the shared helper so the memo re-splice cannot
         * drift from the two HIT sites. The pct argument is 0 because a memo is
         * a COUNTER and the helper's kind gate would refuse to promote it
         * anyway -- passing 0 states that intent locally, and means this site
         * needs no access to the location config. If the kind gate were ever
         * dropped, the promote-on-second-hit test asserts BOTH this path and
         * the gate, so the regression is caught either way. */
        ngx_http_cache_turbo_shm_touch_lru(z, ctn, now, 0, hash);
    }

    ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));

    return rc;
}


/* COR-5(b): arm/disarm the variant-index self-heal flag on one ENTRY node.
 *
 * Gated on kind == ENTRY on purpose. The flag means "the SADD naming THIS
 * body's L2 key never reached the wire"; a COUNTER or an in-flight stub holds
 * no body, so there is nothing for a purge to miss and nothing to re-index --
 * arming it there would just make a later hit fire a pointless op. */
void
ngx_http_cache_turbo_shm_varidx_pending_set(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, ngx_uint_t pending)
{
    ngx_http_cache_turbo_node_t  *ctn;

    ngx_shmtx_lock(ngx_http_cache_turbo_zone_mutex(z));

    ctn = ngx_http_cache_turbo_shm_lookup(z, key_hash, hash);

    if (ctn != NULL && ctn->kind == NGX_HTTP_CACHE_TURBO_NODE_ENTRY) {
        ctn->varidx_pending = pending ? 1 : 0;
    }

    ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));
}


/* L2 negative memo (L13). Record that an L2 GET just missed this key, so the
 * next cold request skips the round-trip for `ttl` seconds. Best-effort: a full
 * slab simply means no memo (one extra RTT, never a correctness problem).
 * See the L1 vtable `l2_neg_set` comment. */
void
ngx_http_cache_turbo_shm_l2_neg_set(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, time_t ttl)
{
    time_t                        now;
    ngx_http_cache_turbo_node_t  *ctn;

    now = ngx_time();

    ngx_shmtx_lock(ngx_http_cache_turbo_zone_mutex(z));

    ctn = ngx_http_cache_turbo_shm_lookup(z, key_hash, hash);

    if (ctn != NULL) {
        /* Never memo an ENTRY: it holds a body, so it does not consult L2 at all
         * and a memo on it could never be read.
         *
         * ⚠ `refreshing` is deliberately NOT consulted here either. The old guard
         * rejected a refreshing node because "stamping a stub would make the memo
         * outlive the single-flight it belongs to" -- but outliving it is now the
         * INTENDED behaviour (see l2_neg_check and the claim() takeover branch):
         * the memo describes L2's contents and a local regen does not change them.
         * Keeping the guard would also re-create the ~1-request window from the
         * other side, since a cold request's own claim() marks the node before the
         * miss is recorded on some paths.
         *
         * C3: MARKER joins this guard for the identical reason. This function is
         * called with the marker key too (access.c's marker-consult "definitive
         * miss" arm, ctx->vary_marker_key) -- and a MARKER, exactly like an
         * ENTRY, holds real content (the [bits][gen] pair): if a peer request
         * concurrently landed a fresh marker at this exact key between this
         * call's own L1 miss a moment earlier and this memo write, stamping a
         * memo over it would be pure pollution (the field would never again be
         * read, since any later request finds the live marker straight from L1
         * and never reaches this memo check at all) -- but skipping it here,
         * the same way an ENTRY always has, costs nothing and keeps this
         * function's contract uniform across both kinds that "hold content". */
        if (ctn->kind == NGX_HTTP_CACHE_TURBO_NODE_ENTRY
            || ctn->kind == NGX_HTTP_CACHE_TURBO_NODE_MARKER)
        {
            ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));
            return;
        }

        ctn->l2_neg_until = now + ttl;
        ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));
        return;
    }

    /* No node yet: create a COUNTER carrying only the memo. Invisible to every
     * serve branch (they require an ENTRY with a body). miss_count stays 0 --
     * this path counts nothing; if min_uses is also on it will do its own
     * counting through count_miss on the same node. */
    ctn = ngx_http_cache_turbo_shm_alloc_evict(z,
              sizeof(ngx_http_cache_turbo_node_t));
    if (ctn == NULL) {
        ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));   /* out of slab: no memo */
        return;
    }

    ctn->node.key = ngx_http_cache_turbo_shm_key64(key_hash);
    ngx_memcpy(ctn->key, key_hash, 32);
    ctn->kind = NGX_HTTP_CACHE_TURBO_NODE_COUNTER;
    ctn->data = NULL;
    ctn->len = 0;
    ctn->fresh_until = 0;
    ctn->stale_until = 0;
    ctn->refreshing = 0;
    ctn->refresh_lock_until = 0;
    ctn->refresh_owner = 0;      /* CTXRDR-ADOPT-LEASE: a memo holds no lease */
    ctn->miss_count = 0;
    ctn->l2_neg_until = now + ttl;
    ctn->last_access = now;      /* P1: init the coarse LRU stamp */
    ctn->promotable = 0;         /* S8: unproven; second touch promotes */
    ctn->hash_crc32 = hash;      /* PERF-AUD2-10: save the recompute */
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    /* PERF-AUD2-10 invariant check: the documented contract (struct
     * field comment above, shm_admit() comment) is that `hash` equals
     * ngx_crc32_short(key_hash, 32) for this node's own key. Bounded
     * blast radius, not a correctness bug -- shm_lookup() discards its
     * `hash` parameter and descends on the widened key64 instead, so a
     * mismatch here can never mis-route a lookup or cross-serve
     * another key's object; the only consequence is shm_admit()
     * consulting the wrong W-TinyLFU sketch rows for this node as a
     * future eviction victim, degrading admission accuracy. Same
     * TEST_FAULTS diagnostic-counter convention as
     * breaker_wedge_observed (O4.4-i/H-2). */
    if (ngx_crc32_short(key_hash, 32) != hash) {
        (void) ngx_atomic_fetch_add(
            &ngx_http_cache_turbo_zone_sh(z)->test_hash_crc32_mismatch, 1);
    }
#endif

    ngx_rbtree_insert(&ngx_http_cache_turbo_zone_sh(z)->rbtree, &ctn->node);
    /* S8: every new node enters PROBATION (see lru_insert_new). */
    ngx_http_cache_turbo_lru_insert_new(z, ctn);

    ngx_shmtx_unlock(ngx_http_cache_turbo_zone_mutex(z));
}


/*
 * P6/O4.1 -- circuit-breaker state machine. Per-zone (D-5).
 *
 * CLOSED --(threshold failures inside window)--> OPEN
 *   OPEN --(open_for elapsed)--------------->  HALF_OPEN   (one probe allowed)
 * HALF_OPEN --(probe succeeded)------------->  CLOSED
 * HALF_OPEN --(probe failed)---------------->  OPEN        (fresh open window)
 * HALF_OPEN --(lease expired, probe never reported)--> OPEN (reclaim)
 *
 * ⚠ O4.4-a: the two durations above are INDEPENDENT. open_for drives the
 * OPEN -> HALF_OPEN edge; the reclaim edge is driven by the internal
 * NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_LEASE. Driving both from open_for let a
 * probe slower than open_for be reclaimed mid-flight, which wedged the breaker
 * permanently OPEN against a slow-but-healthy origin.
 *
 * ⚠ NO LOCK IS TAKEN HERE, deliberately -- see the field block in module.h.
 * Every transition is one ngx_atomic_cmp_set on sh->breaker_state; the losing
 * worker of a concurrent CAS simply observes the winner's state on its next
 * read. That makes the transitions correct under concurrency without making
 * the FIELDS mutually consistent, so no caller may latch two of them and
 * assume they describe one instant.
 *
 * ⚠ O4.4-b: every deadline test here is written as `now - stamp CMP duration`,
 * never `now CMP stamp + duration`. ngx_parse_time() accepts durations up to
 * NGX_MAX_INT_T_VALUE, so adding one to an epoch stamp overflows signed time_t
 * and SILENTLY INVERTS the comparison -- a very large breaker_window would read
 * as permanently elapsed rather than never. Subtracting an epoch stamp from
 * another epoch stamp cannot overflow, so the elapsed form is safe for every
 * duration the parser can produce, and no range check on the directives is
 * needed. Keep new deadline tests in this form.
 *
 * This is state only. NOTHING on the serve path calls these yet: O4.3 wires
 * the request path, O4.2 wires the outcome recording, O4.4 adds the directives
 * that supply threshold/window/open_for. Until then the breaker is inert by
 * construction -- there is no config that can reach it, which is why O4.1 is
 * safe to merge on its own.
 */

/*
 * Return the breaker's CURRENT state, performing any transition that has become
 * due purely by the passage of time (OPEN -> HALF_OPEN). Callers treat the
 * return value as the verdict for this request.
 *
 * `open_for` is how long an OPEN lasts before one probe is let through. A
 * caller passing 0 disables the timed reopen (the breaker stays OPEN until a
 * recorded success), which is why the guard below is `> 0` and not an assert.
 * It does NOT bound how long the promoted probe may take -- that is the
 * internal NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_LEASE (O4.4-a).
 *
 * Exactly ONE request per open window is promoted to the probe: the CAS on
 * OPEN -> HALF_OPEN has a single winner, and every other request keeps seeing
 * OPEN until that probe reports back through _record(). That is the property
 * that stops a thundering herd from all "probing" a still-dead origin at once.
 */
/*
 * O4.4-h: how long ago the lease carried by `probe_word` was stamped, in
 * seconds. The stamp is RELATIVE to sh->breaker_epoch (see the packed-probe
 * block in the header: an absolute epoch stamp does not fit beside a generation
 * on a 32-bit ngx_atomic_t), so the age is the difference of two relative
 * values and, like every other deadline test in this file, is written as
 * `elapsed CMP duration` rather than `now CMP stamp + duration` -- O4.4-b.
 *
 * ⚠ The subtraction is MODULAR IN THE STAMP FIELD, and it must stay that way.
 * Subtracting a masked stamp from a full-width `now - epoch` looks equivalent
 * and is not: once the relative clock passes the field's range, a lease stamped
 * moments ago reads as a whole field-width old and is reclaimed on the spot --
 * on the 20-bit (32-bit atomic) layout that is roughly every twelve days, and
 * it would be reached by an ordinary long-lived zone rather than by any attack.
 * Masking both sides keeps the difference correct across a wrap, because the
 * true age is always far smaller than the field.
 *
 * The age is therefore only meaningful for stamps younger than one field wrap,
 * which the lease constant guarantees for any lease this function is asked
 * about. Pinned by test_breaker_probe_age_is_modular().
 *
 * ⚠ H-3: `now` is nginx's cached wall clock (ngx_time()), which follows
 * settimeofday()/NTP steps rather than a monotonic source. A BACKWARDS step
 * to before sh->breaker_epoch makes `now - epoch` negative; cast to
 * ngx_uint_t that wraps to near-UINT_MAX, which then masks to near-MASK --
 * i.e. it reads as an almost-maximally-OLD lease and gets reclaimed while
 * still live. This is the ORIGINAL O4.4-h failure mode, reintroduced by the
 * very epoch anchor that fixed the other one.
 *
 * The fix clamps: when `now` precedes the epoch, the lease is reported as
 * age 0 (brand new) rather than computing a meaningless negative-turned-huge
 * age. That fails CLOSED -- a spuriously "young" reading only means one
 * fewer reclaim opportunity until the clock catches back up, never an
 * incorrect reclaim of a live lease. A monotonic clock source would remove
 * the hazard at its root, but that is a module-wide change out of scope
 * here. Pinned by test_breaker_backwards_clock_step_does_not_reclaim().
 */
static time_t
ngx_http_cache_turbo_shm_brk_probe_age(ngx_http_cache_turbo_zone_t *z,
    ngx_uint_t probe_word, time_t now)
{
    ngx_uint_t  rel, stamp;

    if (now < (time_t) ngx_http_cache_turbo_zone_sh(z)->breaker_epoch) {
        return (time_t) 0;
    }

    rel   = ((ngx_uint_t) (now - (time_t) ngx_http_cache_turbo_zone_sh(z)->breaker_epoch))
            & NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_STAMP_MASK;
    stamp = ngx_http_cache_turbo_brk_probe_stamp(probe_word);

    return (time_t) ((rel - stamp)
                     & NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_STAMP_MASK);
}


ngx_uint_t
ngx_http_cache_turbo_shm_breaker_state(ngx_http_cache_turbo_zone_t *z,
    time_t open_for, ngx_uint_t *probe)
{
    time_t      now;
    ngx_uint_t  word, state, probe_word;

    /* O4.3: default to "no lease". Only the promotion CAS below overwrites
     * this, so every caller that is merely OBSERVING the breaker -- including
     * one that sees a HALF_OPEN installed by somebody else -- goes away without
     * a token and therefore cannot resolve the lease in _breaker_record(). */
    *probe = NGX_HTTP_CACHE_TURBO_BREAKER_NO_PROBE;

    /* Plain volatile read, NOT fetch_add(...,0): a lock-prefixed RMW would
     * acquire the cache line exclusively on every call, and this is the
     * pre-origin-connect read path -- the hottest site in the zone. Sampling is
     * all that is needed here; the transitions below carry their own CAS.
     *
     * O4.3-c: one read of the PACKED word. Both the state and the generation
     * come from the same load, so every CAS below is tested against the exact
     * word this caller decided on -- that is what makes the transitions
     * generation-safe rather than merely state-safe. */
    word  = (ngx_uint_t) ngx_http_cache_turbo_zone_sh(z)->breaker_state;
    state = ngx_http_cache_turbo_brk_state(word);

    /* O4.4-h: one load of the probe word, reused for BOTH the reclaim test
     * below and, as the expected value, for the publication CAS on the
     * promotion path. Re-reading it at either site would reintroduce a
     * mispairing window. */
    probe_word = (ngx_uint_t) ngx_http_cache_turbo_zone_sh(z)->breaker_probe;

    now = ngx_time();

    /* ⚠ A caller that merely OBSERVES a HALF_OPEN installed by somebody else is
     * NOT the probe and must be told OPEN. Returning the stored state here --
     * which an earlier revision did -- hands every concurrent request the
     * probe's verdict and destroys the entire anti-herd property: one worker
     * wins the CAS, and then unbounded traffic walks past the breaker into the
     * dead origin. HALF_OPEN is returned by exactly one path, the successful
     * promotion CAS below, and nowhere else.
     *
     * The exception is a probe that never reported back (its request was
     * aborted, or its worker was killed between promotion and _record()).
     * Nothing would ever move the state again, so the breaker would wedge in
     * HALF_OPEN forever. breaker_probe makes the promotion a time-bounded
     * LEASE: once it has gone stale by BREAKER_PROBE_LEASE, the next caller
     * reclaims the probe slot with a CAS -- again a single winner.
     *
     * ⚠ O4.4-a: the lease duration is that INTERNAL constant and deliberately
     * NOT open_for. Reclaiming on open_for meant any probe slower than it was
     * reclaimed in flight, so a slow-but-healthy origin could never close the
     * breaker. See the constant's block in the header for why it is not a
     * directive. open_for still gates this branch, matching the promotion test
     * below: with open_for == 0 there is no timed reopen, so no probe is ever
     * promoted and there is no lease to reclaim. (The FEATURE switch is
     * breaker_threshold, not this -- see the merge note on breaker_open.) */
    if (state == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN) {

        /* ⚠ O4.4-h: a lease may only be reclaimed on a deadline that PROVABLY
         * belongs to the generation this caller observed. The probe word is read
         * ONCE into a local and carries its own generation, so the two halves of
         * the test cannot come from different leases -- which is exactly the bug
         * this replaced. Reading the field twice here reopens it.
         *
         * The predicate is deliberately three-part:
         *
         *   - generations MATCH: a probe word whose generation is BEHIND belongs
         *     to a lease already superseded (stale mispairing -- the O4.4-h
         *     race); one that runs AHEAD belongs to a promoter that published
         *     its probe word and has not yet won the state CAS. Neither is an
         *     abandoned lease, and both must be left alone.
         *   - the stamp has aged past BREAKER_PROBE_LEASE (O4.4-a: that internal
         *     constant, never open_for -- reclaiming on open_for tore the lease
         *     out from under any probe slower than it, so a slow-but-healthy
         *     origin could never close the breaker).
         *   - the whole state word still CASes, so there is a single winner.
         *
         * ⚠ The explicit NO_PROBE test is NOT redundant with the equality test
         * below it, and removing it reopens the zeroed-zone hole the old
         * `stamp != 0` guard used to cover. A zone whose state word is a bare
         * HALF_OPEN carries generation 0, and a zeroed probe word ALSO reads
         * generation 0 -- so the two "match", the zero stamp reads as ancient,
         * and the brand-new lease is reclaimed. Verified by mutation: dropping
         * this line fails test_breaker_unpublished_lease_is_not_reclaimable().
         * The generation equality alone is therefore necessary but not
         * sufficient; NO_PROBE must be rejected on its own.
         *
         * ⚠⚠ H-2 (resolved -- O4.4-j): a generation MISMATCH (state gen N,
         * probe gen != N, not NO_PROBE) is never reclaimed by this predicate,
         * because the equality arm above requires an exact match before the
         * age test even runs. Every caller reaching the `else` below with a
         * mismatch returns OPEN -- so the fix is making that mismatch
         * unreachable, not teaching this predicate to reclaim it (both tried
         * directions there broke test_breaker_fresh_lease_not_reclaimable_
         * via_old_stamp(), which correctly pins that a momentarily-mismatched
         * FRESH generation must not be torn down on sight).
         *
         * Divergence was traced to exactly one reachable producer:
         *   - The promotion path cannot produce it: `word` and `probe_word`
         *     are loaded ONCE, together, above (see the comment there), and
         *     `gen` is derived from that same snapshot. A promoter working
         *     from a stale snapshot fails its publication CAS below and
         *     writes nothing -- it cannot drive probe.gen backwards or publish
         *     against a generation other than the one it observed.
         *   - _breaker_record()'s three state writers (close, failed-probe,
         *     trip) each write breaker_state alone and never bump the
         *     generation, so none of them can produce a divergent pair either.
         *   - The one real producer is ABA on the MASKED generation field: a
         *     promoter parked between the publish CAS and the state CAS
         *     across a full wrap of the masked generation finds its stale
         *     expectation coincidentally matching again. That wrap is closed
         *     by construction on the 64-bit (32-bit generation) layout and
         *     the 32-bit-atomic layout is rejected at compile time rather
         *     than shipped with a reachable wrap -- see the packed-probe
         *     layout comment in the header for the wrap-period arithmetic
         *     and why no other bit split fixes it.
         * A wedge landing here despite that is therefore now itself the
         * anomaly signal: see the else-branch counter below.
         *
         * Pinned by test_breaker_unpublished_lease_is_not_reclaimable() and
         * test_breaker_fresh_lease_not_reclaimable_via_old_stamp().
         *
         * O4.4-a's open_for gate stays: with open_for == 0 there is no timed
         * reopen, so no probe is ever promoted and there is no lease to
         * reclaim. */
        if (open_for > 0
            && ngx_http_cache_turbo_brk_probe_gen(probe_word)
                   != NGX_HTTP_CACHE_TURBO_BREAKER_NO_PROBE
            && ngx_http_cache_turbo_brk_probe_gen(probe_word)
                   == (ngx_http_cache_turbo_brk_gen(word)
                       & NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_GEN_MASK)
            && ngx_http_cache_turbo_shm_brk_probe_age(z, probe_word, now)
                   >= (time_t) NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_LEASE
            && ngx_atomic_cmp_set(&ngx_http_cache_turbo_zone_sh(z)->breaker_state, (ngx_atomic_uint_t) word,
                                  (ngx_atomic_uint_t)
                                      ngx_http_cache_turbo_brk_pack(
                                          ngx_http_cache_turbo_brk_gen(word),
                                          NGX_HTTP_CACHE_TURBO_BREAKER_OPEN)))
        {
            /* Reclaimed an abandoned lease by demoting it to OPEN. Exactly one
             * caller can win THIS cas (the next one finds OPEN, not
             * HALF_OPEN), and that winner then falls through to the ordinary
             * promotion path below, which re-stamps opened_at and admits one
             * replacement probe. Two CASes rather than one, but each has a
             * genuine single winner -- a HALF_OPEN -> HALF_OPEN cas would
             * succeed for every caller and guard nothing.
             *
             * ⚠ This stamp lands AFTER its CAS, the opposite of the ordering
             * _breaker_record() insists on, and it is safe ONLY because of the
             * VALUE: now - open_for reads as already elapsed, so a worker that
             * sees the intermediate OPEN with an even older opened_at just wins
             * the promotion CAS instead of us -- still exactly one probe.
             * Change this to `now`, or to anything meant to arm a FRESH window,
             * and the ordering silently becomes the window-skip bug the
             * failed-probe path warns about. Move the write above the CAS if
             * you ever change the value. */
            ngx_http_cache_turbo_zone_sh(z)->breaker_opened_at = (ngx_atomic_t) (now - open_for);

            /* O4.3-c: we own the demotion, so we know the word we installed --
             * same generation, state now OPEN. Fall through to the promotion
             * below and CAS against THAT, not against the pre-reclaim word. */
            word  = ngx_http_cache_turbo_brk_pack(
                        ngx_http_cache_turbo_brk_gen(word),
                        NGX_HTTP_CACHE_TURBO_BREAKER_OPEN);
            state = NGX_HTTP_CACHE_TURBO_BREAKER_OPEN;

        } else {
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
            /* H-2/O4.4-j: this else is reached whenever the reclaim arm above
             * failed, for ANY of its conjuncts. Count it as a wedge candidate
             * only for the actual mismatch case -- NOT the "no probe yet"
             * (NO_PROBE) or "probe still fresh" (age < LEASE) cases, which
             * also fall through here on every ordinary request and would
             * swamp the counter with non-events.
             *
             * ⚠ open_for > 0 must be re-tested here, and it is not redundant
             * with the arm above: it is that arm's FIRST conjunct, so with the
             * timed reopen disabled the predicate short-circuits straight into
             * this else. A probe word left mismatched by an earlier
             * configuration (a lease published before breaker_open was set to
             * 0 across a reload) would then bump on every single request.
             * Nothing is wedged in that state -- with no timed reopen there is
             * no promotion to be starved of -- and a counter that ticks up
             * forever in a working deployment is not an anomaly signal. */
            if (open_for > 0
                && ngx_http_cache_turbo_brk_probe_gen(probe_word)
                    != NGX_HTTP_CACHE_TURBO_BREAKER_NO_PROBE
                && ngx_http_cache_turbo_brk_probe_gen(probe_word)
                       != (ngx_http_cache_turbo_brk_gen(word)
                           & NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_GEN_MASK))
            {
                (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->breaker_wedge_observed, 1);
            }
#endif
            return NGX_HTTP_CACHE_TURBO_BREAKER_OPEN;
        }
    }

    if (state != NGX_HTTP_CACHE_TURBO_BREAKER_OPEN || open_for <= 0) {
        return state;
    }

    if (now - (time_t) ngx_http_cache_turbo_zone_sh(z)->breaker_opened_at < open_for) {
        return NGX_HTTP_CACHE_TURBO_BREAKER_OPEN;
    }

    /* The open window has elapsed. Promote exactly one request to probe the
     * origin. A loser of this CAS keeps its OPEN verdict -- it must NOT fall
     * through to the origin, or the herd this breaker exists to stop walks
     * straight past it. */
    {
        ngx_uint_t  gen, next;

        /* O4.3-c: the promotion opens a NEW lease generation, and the CAS
         * covers state and generation together. A loser sees the winner's whole
         * word and retries nothing -- it simply keeps its OPEN verdict.
         *
         * ⚠ The generation starts at 1, never 0: 0 is the NO_PROBE sentinel, so
         * a zeroed zone's first promotion must not hand out a token that reads
         * as "no lease held". Wrapping past 2^62 lands back on 0 for the same
         * reason, hence the explicit skip rather than a bare increment. */
        /* ⚠ O4.4-h: the skip must hold for the MASKED generation too. The probe
         * word carries only the low PROBE_GEN_BITS of the generation, so a full
         * generation whose masked value is 0 would publish a probe word reading
         * NO_PROBE that never matches its own state word -- and that lease could
         * then never be reclaimed. Skipping on the masked value keeps both
         * widths consistent, at a cost of one extra promotion per wrap of the
         * narrow field. */
        gen = ngx_http_cache_turbo_brk_gen(word) + 1;
        if (gen == NGX_HTTP_CACHE_TURBO_BREAKER_NO_PROBE
            || (gen & NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_GEN_MASK)
                   == NGX_HTTP_CACHE_TURBO_BREAKER_NO_PROBE)
        {
            gen++;
            if (gen == NGX_HTTP_CACHE_TURBO_BREAKER_NO_PROBE) {
                gen = 1;
            }
        }

        next = ngx_http_cache_turbo_brk_pack(
                   gen, NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN);

        /* ⚠ O4.4-h: PUBLISH THE PROBE WORD BEFORE THE STATE CAS. The ordering
         * is load-bearing and it is the REVERSE of what this code did before.
         *
         * Stamping after the CAS left a window in which a concurrent reader saw
         * the fresh HALF_OPEN paired with the PREVIOUS lease's expired stamp and
         * reclaimed a lease milliseconds old. The generation did not save it,
         * because nothing tied the stamp TO a generation -- the reader's reclaim
         * CAS named the word it had loaded, which was current, so it SUCCEEDED.
         * (The comment that used to sit here claimed such a reader "is testing
         * against generation N-1 and loses". It had loaded N. Do not restore
         * that reasoning.)
         *
         * Publishing first inverts the failure direction. A probe word whose
         * generation runs AHEAD of the state word is inert by construction: the
         * reclaim branch demands the generations MATCH, so a promoter that
         * publishes here and then LOSES the CAS below leaves nothing any reader
         * will act on, and the next promotion overwrites it. Hence no rollback
         * on a lost CAS.
         *
         * ⚠ This publication is a CAS, not a plain store, and the difference is
         * a real race rather than caution. Promoters racing the same word all
         * derive the SAME generation from it, so a plain store lets a DELAYED
         * LOSER land its own stamp on top of the winner's afterwards -- same
         * generation, so the reclaim branch's equality test cannot tell them
         * apart, and the winner's live lease silently inherits a stamp it never
         * wrote. Expecting the prior word makes exactly one publication succeed;
         * a loser's CAS fails and it writes nothing.
         *
         * A failed publication CAS means somebody else already published for
         * this generation, so this caller must NOT go on to claim the lease --
         * it returns OPEN and lets the winner probe.
         *
         * ⚠ The stamp is RELATIVE to breaker_epoch -- see the packed-probe block
         * in the header for why an absolute epoch stamp cannot sit beside a
         * generation on a 32-bit ngx_atomic_t. */
        if (!ngx_atomic_cmp_set(&ngx_http_cache_turbo_zone_sh(z)->breaker_probe,
                                (ngx_atomic_uint_t) probe_word,
                                (ngx_atomic_uint_t)
                                    ngx_http_cache_turbo_brk_probe_pack(
                                        gen,
                                        (ngx_uint_t) (now
                                            - (time_t) ngx_http_cache_turbo_zone_sh(z)->breaker_epoch))))
        {
            return NGX_HTTP_CACHE_TURBO_BREAKER_OPEN;
        }

        if (ngx_atomic_cmp_set(&ngx_http_cache_turbo_zone_sh(z)->breaker_state, (ngx_atomic_uint_t) word,
                               (ngx_atomic_uint_t) next))
        {
            /* O4.4-h: the lease deadline was already published above, together
             * with this generation, in one word. Nothing is stamped here -- a
             * store after this CAS is exactly the bug that was fixed. */

            /* The GENERATION is the lease token, not the stamp. Two leases
             * promoted in the same wall-clock second are stamp-equal, which is
             * precisely the collision that let a superseded probe resolve a
             * replacement lease. Generations are unique by construction. */
            *probe = gen;

            return NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN;
        }
    }

    return NGX_HTTP_CACHE_TURBO_BREAKER_OPEN;
}


/*
 * Feed one origin outcome into the breaker. `success` is non-zero when the
 * origin answered acceptably; zero when it failed (connect error, timeout, or
 * a status the use_stale mask counts as down).
 *
 * `threshold` failures inside a `window` of seconds trip CLOSED -> OPEN. The
 * window is a rolling anchor, not a fixed bucket: the first failure after an
 * idle gap re-anchors it, so a slow trickle of unrelated failures spread over
 * hours never accumulates into an open. A threshold of 0 disables tripping,
 * and so does a window of 0 -- both are inert rather than degenerate.
 */
void
ngx_http_cache_turbo_shm_breaker_record(ngx_http_cache_turbo_zone_t *z,
    ngx_uint_t success, ngx_uint_t threshold, time_t window, ngx_uint_t probe)
{
    time_t            now;
    ngx_atomic_uint_t fails, window_start;
    ngx_uint_t        word, state;

    now   = ngx_time();
    /* O4.3-c: one read of the packed word; state and generation are decided
     * together, and every CAS below is tested against this exact value. */
    word  = (ngx_uint_t) ngx_http_cache_turbo_zone_sh(z)->breaker_state;   /* plain read, see above */
    state = ngx_http_cache_turbo_brk_state(word);

    if (success) {
        /* A success clears the failure run. */
        ngx_http_cache_turbo_zone_sh(z)->breaker_fails = 0;

        /* ⚠ ONLY a HALF_OPEN -> CLOSED edge exists, matching the state diagram.
         * An earlier revision closed from ANY non-CLOSED state, which let a
         * success that had been in flight since before the trip close a breaker
         * it knew nothing about: a slow request started while CLOSED completes
         * after faster failures opened the breaker, and reports "origin fine".
         * While OPEN nobody is talking to the origin by construction, so the
         * only success that carries current information is the probe's. Any
         * other success is stale by definition and must be ignored.
         *
         * This is deliberately NOT a full generation/token scheme. A stale
         * probe success can still close a LATER HALF_OPEN (classic ABA: the
         * state returned to HALF_OPEN while the old outcome was in flight).
         * Closing early costs one round of origin traffic that immediately
         * re-trips, whereas the pre-trip case above could hold the breaker
         * closed against a dead origin indefinitely. O4.3 owns the probe
         * token if the residual turns out to matter in practice; it needs a
         * request-scoped handle this API does not have. */
        /* ⚠ O4.3: ONLY the request holding this lease's token may close it.
         * Without the token check any success completing during HALF_OPEN
         * closes the breaker -- including a request that began BEFORE the trip
         * and whose "origin fine" verdict is stale by definition, and a
         * concurrent request that was served from a peer's L2 fill and never
         * touched the origin at all. Both release the herd toward an origin
         * nothing actually probed. The token is the promotion's own stamp, so a
         * leftover token from a previous lease fails this comparison too, which
         * closes the ABA case the O4.1 comment flagged as residual. */
        /* ⚠ O4.3-c: the token is the lease GENERATION, and the CAS carries it.
         * Comparing against the probe STAMP was not enough -- the stamp is a
         * wall-clock second, so a superseded probe and its replacement are
         * stamp-EQUAL whenever both promotions land in the same second, and the
         * old probe's state-only CAS then closed a lease it did not own. Testing
         * the whole word means a resolution can only land on the exact
         * generation it was issued for. */
        if (state == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN
            && probe != NGX_HTTP_CACHE_TURBO_BREAKER_NO_PROBE
            && probe == ngx_http_cache_turbo_brk_gen(word))
        {
            (void) ngx_atomic_cmp_set(&ngx_http_cache_turbo_zone_sh(z)->breaker_state,
                                      (ngx_atomic_uint_t) word,
                                      (ngx_atomic_uint_t)
                                          ngx_http_cache_turbo_brk_pack(
                                              probe,
                                              NGX_HTTP_CACHE_TURBO_BREAKER_CLOSED));
        }

        return;
    }

    /* --- failure --- */

    if (state == NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN
        && probe != NGX_HTTP_CACHE_TURBO_BREAKER_NO_PROBE
        && probe == ngx_http_cache_turbo_brk_gen(word))
    {
        /* The probe failed: back to OPEN for a fresh window. Re-stamping
         * opened_at is what makes the next probe wait another open_for rather
         * than firing again immediately.
         *
         * ⚠ The timestamp is published BEFORE the CAS. Written after, a worker
         * could observe the new OPEN while opened_at still held the PREVIOUS
         * open's value, compute that open_for had long since elapsed, and
         * promote a probe immediately -- skipping the entire window. Writing
         * first means any worker that can see OPEN can already see a deadline
         * that is at least as new. */
        ngx_http_cache_turbo_zone_sh(z)->breaker_opened_at = (ngx_atomic_t) now;

        (void) ngx_atomic_cmp_set(&ngx_http_cache_turbo_zone_sh(z)->breaker_state,
                                  (ngx_atomic_uint_t) word,
                                  (ngx_atomic_uint_t)
                                      ngx_http_cache_turbo_brk_pack(
                                          probe,
                                          NGX_HTTP_CACHE_TURBO_BREAKER_OPEN));

        return;
    }

    /* O4.3: a failure during HALF_OPEN from someone who does NOT hold the lease
     * lands here and is dropped by the state test below. That is deliberate and
     * symmetric with the success side: while HALF_OPEN, the only outcome
     * carrying current information about the origin is the probe's. A non-probe
     * failure is either older than the trip or belongs to a request that never
     * reached the origin, and letting it re-stamp opened_at would push the next
     * probe out by a full open_for on evidence nobody gathered.
     *
     * ⚠ window <= 0 is INERT, not "count forever". Skipping the re-anchor
     * instead would let breaker_fails accumulate for the life of the zone and
     * trip on the Nth failure EVER recorded, days apart -- precisely the slow
     * trickle the rolling window exists to ignore. O4.4 feeds these values from
     * directives, so an unset or zero window is a plausible arrival, and it
     * must fail towards "breaker does nothing" like threshold == 0 does. */
    if (state != NGX_HTTP_CACHE_TURBO_BREAKER_CLOSED
        || threshold == 0 || window <= 0)
    {
        return;
    }

    /* Rolling window: re-anchor if the previous one has expired, so only a
     * BURST of failures trips the breaker.
     *
     * ⚠ O4.5: the re-anchor is a CAS, and ONLY the worker that wins it clears
     * the counter. The plain check-then-write this replaced was a read-modify-
     * write with no exclusion, so every worker whose read saw the expired
     * anchor executed BOTH stores. During exactly the burst the window exists
     * to catch, N workers re-zero the counter as fast as they increment it: the
     * count never reaches threshold and the breaker stays CLOSED against a dead
     * origin. The failure direction is "misses a real outage", not "trips
     * early", which is why it survived every single-threaded test here.
     *
     * A loser does NOT retry and does NOT clear. It falls through to the
     * fetch_add and counts into the window the winner just opened -- the
     * correct window for it, since its failure is concurrent with the winner's
     * rather than older. Losing the CAS is the normal path, not an error.
     *
     * The winner clears the counter AFTER winning. Clearing before the CAS
     * would restore the bug outright: losers would clear too, and their stores
     * can land after the winner's fetch_add.
     *
     * ⚠ RESIDUAL, deliberately accepted: the winner's clear is not atomic with
     * its CAS, so a loser's fetch_add landing in that gap is erased. nginx
     * exposes only cmp_set and fetch_add on ngx_atomic_t -- there is no atomic
     * exchange -- so closing it would need a lock on the header-filter path,
     * far too expensive for the failure path of an advisory counter. The
     * residual is BOUNDED: at most the failures racing one re-anchor, once per
     * window, and it can only DELAY a trip, never cause a spurious one. The
     * STATE transitions below are the part that must be exact; those are CAS. */
    window_start = (ngx_atomic_uint_t) ngx_http_cache_turbo_zone_sh(z)->breaker_window_start;

    if (now - (time_t) window_start >= window
        && ngx_atomic_cmp_set(&ngx_http_cache_turbo_zone_sh(z)->breaker_window_start,
                              window_start, (ngx_atomic_uint_t) now))
    {
        ngx_http_cache_turbo_zone_sh(z)->breaker_fails = 0;
    }

    fails = (ngx_atomic_uint_t) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->breaker_fails, 1) + 1;

    if (fails < threshold) {
        return;
    }

    /* Same publish-before-CAS ordering as the failed-probe path above: a worker
     * must never be able to see OPEN alongside a stale opened_at and conclude
     * the open window has already expired. */
    ngx_http_cache_turbo_zone_sh(z)->breaker_opened_at = (ngx_atomic_t) now;

    /* ⚠ O4.3-c: CAS the whole packed word, carrying the CURRENT generation
     * forward. Expecting a bare CLOSED here would compare against generation 0
     * and so fail on every zone that has ever run a probe -- the breaker would
     * trip exactly once in the lifetime of the zone and then never again.
     * The trip does not open a new LEASE (no probe is promoted yet), so the
     * generation is preserved rather than bumped; the promotion that follows
     * open_for seconds later is what opens the next one. */
    if (ngx_atomic_cmp_set(&ngx_http_cache_turbo_zone_sh(z)->breaker_state,
                           (ngx_atomic_uint_t)
                               ngx_http_cache_turbo_brk_pack(
                                   ngx_http_cache_turbo_brk_gen(word),
                                   NGX_HTTP_CACHE_TURBO_BREAKER_CLOSED),
                           (ngx_atomic_uint_t)
                               ngx_http_cache_turbo_brk_pack(
                                   ngx_http_cache_turbo_brk_gen(word),
                                   NGX_HTTP_CACHE_TURBO_BREAKER_OPEN)))
    {
        ngx_http_cache_turbo_zone_sh(z)->breaker_fails = 0;
        (void) ngx_atomic_fetch_add(&ngx_http_cache_turbo_zone_sh(z)->breaker_opens, 1);
    }
}


/* Map a breaker state to the string the admin JSON exposes. Returns a static
 * literal; never NULL, so a corrupted state renders as "unknown" rather than
 * crashing the admin endpoint. */
const char *
ngx_http_cache_turbo_shm_breaker_state_str(ngx_uint_t state)
{
    /* O4.3-c: accepts either a bare state or a packed [gen|state] word --
     * masking a bare state is a no-op, so every caller is correct without
     * having to know which it holds. The admin JSON passes the raw shm word. */
    state = ngx_http_cache_turbo_brk_state(state);

    switch (state) {
    case NGX_HTTP_CACHE_TURBO_BREAKER_CLOSED:    return "closed";
    case NGX_HTTP_CACHE_TURBO_BREAKER_OPEN:      return "open";
    case NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN: return "half-open";
    default:                                     return "unknown";
    }
}


/* L1 backend instance (v4-1). Stateless dispatch table over the shm functions
 * above; the zone is always passed in as an argument.
 *
 * ⚠ POSITIONAL: fields are brace-initialised in declaration order. A new slot
 * must be APPENDED here in the same order it was appended to
 * ngx_cache_turbo_l1_backend_t, or every entry after it silently shifts. */
ngx_cache_turbo_l1_backend_t  ngx_http_cache_turbo_shm_backend = {
    ngx_string("shm"),
    ngx_http_cache_turbo_shm_lookup,
    ngx_http_cache_turbo_shm_store,
    ngx_http_cache_turbo_shm_store_if,
    ngx_http_cache_turbo_shm_purge_key,
    ngx_http_cache_turbo_shm_purge_all,
    ngx_http_cache_turbo_shm_stats,
    ngx_http_cache_turbo_shm_claim,
    ngx_http_cache_turbo_shm_count_miss,
    ngx_http_cache_turbo_shm_resolve_miss,
    ngx_http_cache_turbo_shm_l2_neg_check,
    ngx_http_cache_turbo_shm_l2_neg_set,
    ngx_http_cache_turbo_shm_freshen,
};

#pragma GCC visibility pop
