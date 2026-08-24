/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * http-cache-turbo — Varnish-grade edge cache for nginx.
 *
 * v1 vertical slice: L1 shared-memory page cache with stale-while-revalidate
 * and probabilistic single-flight refresh (the "XFetch dice" ported from the
 * wp-redis SWR implementation: eilandert/wp-redis/includes/class-swr.php).
 * No Redis L2, no tags, no REST admin, no presets yet — those land in later
 * versions. See memory/nginx+angie/cache-turbo-module-design.md.
 */

#ifndef NGX_HTTP_CACHE_TURBO_MODULE_H_INCLUDED_
#define NGX_HTTP_CACHE_TURBO_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>


/* R5-1 (perf-microtier-hitpath): the module build has no per-addon CFLAGS hook
 * anywhere in nginx's `auto/module`/`auto/make` — every module object is
 * compiled with the SAME global $(CFLAGS) as nginx core, in both the
 * DYNAMIC (.so) and static --add-module arms (verified against the generated
 * objs/Makefile: our objects and core's use one shared $(CFLAGS) variable).
 * Appending -fvisibility=hidden to that global CFLAGS in `config` would also
 * hide nginx core's own symbols in the static-build arm, which is out of
 * scope and unsafe. Each ngx_http_cache_turbo_*.c wraps ITS OWN body in a
 * `#pragma GCC visibility push(hidden)` / `pop` instead (see those files) —
 * that hides every definition in the TU regardless of whether it has a
 * header prototype, which a header-only pragma does NOT (verified: a pragma
 * around a declaration hides only definitions whose defining declaration is
 * textually inside the pushed region; most of this module's internal
 * functions are declared only by their own definition, with no header
 * prototype, so a header-level pragma left them exported). Only the nginx
 * module struct is opted back to default visibility below. nginx's
 * dynamic-module loader (ngx_load_module in nginx's src/core/nginx.c)
 * resolves exactly three symbols by name via dlsym(): `ngx_modules`,
 * `ngx_module_names`, `ngx_module_order`. All three live in the
 * auto-generated ngx_http_cache_turbo_module_modules.c (nginx's own build
 * glue, not one of our TUs, so unaffected by any of these pragmas), which
 * takes `&ngx_http_cache_turbo_module`'s address into that ngx_modules[]
 * array — a reference resolved by the LINKER at .so-build time, not by a
 * second dlsym. Empirically (2026-08-24 negative control on this branch),
 * hiding the struct itself did NOT stop nginx from dlopen()ing and serving
 * through the module: an intra-DSO, link-time address-of still works when
 * the referencing TU (_modules.c) and the referenced symbol are linked into
 * the same .so, regardless of the symbol's own visibility. The attribute
 * below is kept anyway as defense-in-depth against a future refactor that
 * moves the struct's only reference behind an actual dlsym() (or into a
 * different .so), where hidden visibility would silently break loading. */


/* Stale window = fresh TTL * (STALE_MULTIPLIER - 1), matching wp-redis. This is
 * the BALANCED-preset stale multiplier; presets override it per-band (v3-2) via
 * the runtime ngx_http_cache_turbo_loc_conf_t.stale_mult field. */
#define NGX_HTTP_CACHE_TURBO_STALE_MULTIPLIER  4

/* Bounds on an explicit cache_turbo_stale_mult N. The floor is 1 ("no stale
 * window": stale_ttl == fresh_ttl, nothing is ever served stale) because
 * ngx_http_cache_turbo_stale_ttl() coerces <= 0 back to the BALANCED default,
 * so a literal 0 would silently mean 4 rather than what the operator wrote.
 * The ceiling matches the largest band multiplier and keeps
 * FOREVER_TTL * stale_mult inside the uint32 blob stale_ttl field. */
#define NGX_HTTP_CACHE_TURBO_STALE_MULT_MIN  1
#define NGX_HTTP_CACHE_TURBO_STALE_MULT_MAX  8

/* Bounds on an explicit cache_turbo_min_uses N (H3c). The floor is 1 ("store on
 * the first miss" = feature off) for the same reason stale_mult's floor is 1:
 * merge_loc_conf coerces < 1 up to 1, so a literal 0 or a negative would
 * silently mean 1 rather than what the operator wrote — range-check at parse
 * instead of letting the config lie. The ceiling is a sanity bound: each cold
 * miss below the threshold is an uncached origin fetch, so a large N is far more
 * likely a typo than an intent, and every miss up to N also pins a counter node
 * in the zone. */
#define NGX_HTTP_CACHE_TURBO_MIN_USES_MIN  1
#define NGX_HTTP_CACHE_TURBO_MIN_USES_MAX  32

/* Bounds on cache_turbo_min_uses_window N (P3-6). 0 = OFF (disable windowing,
 * miss_count persists until LRU eviction — v15 behavior). 1..86400 enables
 * windowing; resets miss_count on access when `now - last_access > window`.
 * The ceiling is 1 day. An operator typo of "3600" means 1 hour; 86400 means
 * 1 day; there is no use case for windows longer than one day (a cache entry
 * that has not been accessed in 24 hours is practically evicted anyway). */
#define NGX_HTTP_CACHE_TURBO_MIN_USES_WINDOW_MIN  1
#define NGX_HTTP_CACHE_TURBO_MIN_USES_WINDOW_MAX  86400

/* Bounds on cache_turbo_l2_negative_ttl N (L13). 0 = OFF and is the default in
 * every preset -- this is NOT a preset band column, precisely because the memo
 * trades coherence for a round-trip and that trade must be opted into per
 * location, not inherited from a preset name.
 *
 * The ceiling is deliberately small. The memo has no invalidation channel: a
 * peer node storing the key does not clear it, so the window is exactly how
 * long this node can stay blind to a fresh L2 object. Seconds are useful
 * (a cold-key stampede is over in well under one); minutes are a footgun, so
 * the cap keeps an operator's typo from turning L2 off for an hour. */
#define NGX_HTTP_CACHE_TURBO_L2_NEG_TTL_MIN  1
#define NGX_HTTP_CACHE_TURBO_L2_NEG_TTL_MAX  60

/* Bounds on cache_turbo_vary_marker_revalidate N (c-2). 0 = OFF (today's
 * behaviour exactly: a warm L1 marker is trusted unconditionally, no matter
 * its age) and is the default.
 *
 * The ceiling mirrors l2_negative_ttl's reasoning: this directive trades
 * cross-node marker coherence for avoiding a blocking per-request L2 round
 * trip, and the window is exactly how long a peer's PURGE can stay invisible
 * to THIS node after a warm L1 marker resolve. Seconds are the useful range
 * (see c-2 design in issues.md); minutes would let a typo silently widen the
 * cross-node staleness window back toward "unbounded". */
#define NGX_HTTP_CACHE_TURBO_VARY_MARKER_REVALIDATE_MIN  1
#define NGX_HTTP_CACHE_TURBO_VARY_MARKER_REVALIDATE_MAX  60

/* "Forever" fresh TTL. `cache_turbo_valid 0` ("cache forever", per the code's
 * long-standing contract) resolves to this long-but-finite TTL rather than a
 * literal 0 — a literal 0 made the object instantly+permanently STALE and
 * skipped L2 (the L2 blob's stale_ttl was 0 => every L2 hit read as expired).
 * 10 years keeps all the freshness arithmetic (fresh_until, stale window, L2
 * EXPIRE, blob created+age) on the normal path while behaving as "never
 * expires". Bounded so FOREVER * max-preset-stale_mult (8) still fits the uint32
 * blob stale_ttl field (2.5e9 < 4.29e9). */
#define NGX_HTTP_CACHE_TURBO_FOREVER_TTL  ((time_t) 315360000)   /* 10 years */

/* Hard ceiling for any fresh/stale TTL that reaches the wire (STAB-5). The blob
 * fresh_ttl/stale_ttl are uint32 and the redis PX is `<ttl> * 1000`; an
 * unbounded honor_cc max-age or `cache_turbo_valid <huge>` could overflow the
 * uint32 cast or the *1000. Clamp every TTL to UINT32_MAX seconds (~136 yr,
 * itself well past FOREVER): the cast is lossless and `<= 4.29e9 * 1000` (4.29e12)
 * stays inside int64 %T. ngx_http_cache_turbo_stale_ttl clamps its product here;
 * the store path clamps the fresh TTL before the uint32 cast. */
#define NGX_HTTP_CACHE_TURBO_TTL_MAX  ((time_t) 0xFFFFFFFF)

/* Upper bound on cache_turbo_redis keepalive=N (STAB-5). The per-worker pool is
 * `ngx_palloc(N * sizeof(item))`; an unbounded N overflows the size_t multiply
 * into a short allocation that the init loop then writes N items past. 65535
 * idle L2 conns/worker is already absurd; reject anything larger at parse. */
#define NGX_HTTP_CACHE_TURBO_KEEPALIVE_MAX  65535

/* cache_turbo_keep_stale <off|time|forever> (S2.1; read side wired in S2.2).
 * Origin-independent last-resort stale retention: when a response carries no
 * `stale-if-error` window of its own, this becomes the effective
 * stale-if-error window instead of leaving the object with no fallback at
 * all. `off` (0) is the default and reproduces the pre-S2.1 behaviour
 * exactly -- the store path only widens sie_window when this is > 0.
 *
 * No separate MIN/MAX pair: this directive shares the module-wide
 * NGX_HTTP_CACHE_TURBO_TTL_MAX ceiling above (the same uint32-wire-format
 * bound that clamps every other TTL that can reach the L2 blob), because a
 * kept-stale window is stored and clamped exactly like any other TTL once
 * S2.2 starts reading it -- there is no reason for this one knob to carry a
 * tighter, bespoke ceiling the way l2_negative_ttl does (that ceiling exists
 * because THAT memo has no invalidation channel; this window does). */


/* Upper bound on the cache_turbo_redis database index, accepted both as the
 * `db=N` param and as the `/N` DSN suffix. Redis ships `databases 16`, i.e.
 * indices 0..15; a larger value passes parse but makes every L2 op fail at
 * runtime on SELECT, silently, until traffic arrives. Not a memory-safety
 * issue (the %i format target is NGX_INT_T_LEN and the value is a validated
 * non-negative ngx_int_t) -- purely a fail-at-runtime config trap. */
#define NGX_HTTP_CACHE_TURBO_REDIS_DB_MAX   15

/* AUD-MC1: bounds on the L2 key prefix, enforced at config time in BOTH the
 * cache_turbo_redis and cache_turbo_memcached parsers. memcached frames its
 * commands by spaces and CRLF, so a prefix carrying either splits the command;
 * its keys are also capped at 250 bytes. The module's own contract
 * (ngx_http_cache_turbo_memcached.c header) already asserts the composed key is
 * "printable, no spaces/control chars, <=250 bytes" -- the digest half honoured
 * it, the operator-supplied half was checked for emptiness only. KEY_SUFFIX_MAX
 * covers the longest thing the module appends after the prefix (hex digest plus
 * the tag/variant decorations), so the composed key stays inside 250. */
#define NGX_HTTP_CACHE_TURBO_L2_KEY_MAX        250
#define NGX_HTTP_CACHE_TURBO_L2_KEY_SUFFIX_MAX  64

/* PERF-2: bounds on the upstream-controlled cache_turbo_tag value, so one
 * response cannot fan out into an unbounded number of SADD connections. At most
 * MAX_TAGS distinct tags are indexed per store; a token longer than MAX_TAG_LEN
 * is ignored (a real tag name is short). */
#define NGX_HTTP_CACHE_TURBO_MAX_TAGS     16
#define NGX_HTTP_CACHE_TURBO_MAX_TAG_LEN  128

/* Default SWR aggressiveness (beta). 1.0 = refresh probability tracks the
 * elapsed fraction of the stale window directly. */
#define NGX_HTTP_CACHE_TURBO_DEFAULT_BETA      1000   /* fixed-point /1000 */


/*
 * Autotune presets (#10, v3-2). One directive `cache_turbo_preset
 * micro|conservative|balanced|aggressive` sets the default tuning bundle; an
 * explicit knob directive still wins. Vocab matches wp-redis (BALANCED, not
 * "normal"). Values are 1-based so they index ngx_http_cache_turbo_bands[]
 * directly; 0 is unused so a zeroed/UNSET field is never a valid preset.
 */
#define NGX_HTTP_CACHE_TURBO_PRESET_CONSERVATIVE  1
#define NGX_HTTP_CACHE_TURBO_PRESET_BALANCED      2
#define NGX_HTTP_CACHE_TURBO_PRESET_AGGRESSIVE    3
#define NGX_HTTP_CACHE_TURBO_PRESET_MICRO         4

/* Default-of-defaults: an unconfigured location resolves to BALANCED, whose band
 * values equal the historical hardcoded merge fallbacks (valid 60s, beta 1000,
 * lock_ttl 5s, stale_mult 4). */
#define NGX_HTTP_CACHE_TURBO_PRESET_DEFAULT  NGX_HTTP_CACHE_TURBO_PRESET_BALANCED


/*
 * "cache_turbo_backend none;" — explicitly NO preset here.
 *
 * This is a sentinel, not a registry row: it matches no backend and pulls in no
 * cookie/URI/arg rules. It exists because backend_presets uses 0 to mean "this
 * location named no backend", which the loc-conf merge treats as "inherit the
 * parent's". So a server-level `cache_turbo_backend wordpress;` is inherited by
 * every location under it, and before `none` there was no way to switch that off
 * for one location — leaving the mask at 0 is indistinguishable from silence.
 *
 * NONE occupies a bit so that backend_presets != 0 and inheritance is defeated,
 * while matching nothing in the registry (whose rows all have a real backend
 * bit). It is deliberately OUTSIDE the contiguous preset run so BACKEND_ALL —
 * and the fuzzer's gapless-bits assert — is unaffected.
 *
 * It sits at bit 63, the far end of the widened mask, NOT immediately above the
 * highest preset. It used to be bit 31 when the run was 32-bit, which made it
 * the very next bit a new preset would claim; pinning it to the top instead
 * means the run can grow to 63 presets without a second collision. Do not
 * "tidy" it back down next to the run.
 *
 * It also does NOT imply cache_turbo_cache_control honor, unlike a real preset:
 * asking for no CMS classification should not quietly change how the response's
 * Cache-Control is treated.
 */
#define NGX_HTTP_CACHE_TURBO_BACKEND_NONE         0x8000000000000000ull

/* True when a REAL preset is active — i.e. at least one registry row is armed.
 * Use this, never a bare `backend_presets != 0`: the NONE sentinel is non-zero
 * (deliberately, to defeat loc-conf inheritance) but must not count as a preset,
 * or it would imply cache_control honor and enter the auto-classify walk. */
#define NGX_HTTP_CACHE_TURBO_HAS_BACKEND(m)                                    \
    (((m) & ~NGX_HTTP_CACHE_TURBO_BACKEND_NONE) != 0)

/* cache_turbo_cache_control modes (loc_conf.cc_mode). */
#define NGX_HTTP_CACHE_TURBO_CC_RESPECT  0
#define NGX_HTTP_CACHE_TURBO_CC_HONOR    1
#define NGX_HTTP_CACHE_TURBO_CC_IGNORE   2


/*
 * Live autotune within preset bands (#10, v4-3). Ported from the wp-redis PHP
 * implementation (eilandert/wp-redis/includes/class-swr-autotune.php) so the edge
 * cache and the object cache tune the same way with the same constants. When
 * cache_turbo_autotune is on, a throttled per-zone recompute reads the L1 shm
 * stats over the last window (delta-snapshot), derives a target beta from the
 * average origin-regen cost, and writes it to the zone (z->sh->autotuned_beta).
 * The request path then uses that beta clamped to the location's preset band
 * instead of the static preset/explicit beta. See history.md v4-3.
 *
 * All values are integer fixed-point to keep floats off the request path, exactly
 * like swr.c: beta is ×1000, hit-rate is a percentage, the cost divisor and churn
 * cap are plain integers. The PHP source uses 0.5/3.0/20/30ms/10ms/100/0.95/2.0.
 */
#define NGX_HTTP_CACHE_TURBO_BETA_MIN          500    /* 0.5 ×1000 (global floor) */
#define NGX_HTTP_CACHE_TURBO_BETA_MAX          3000   /* 3.0 ×1000 (global ceil)  */
#define NGX_HTTP_CACHE_TURBO_BETA_COST_DIVISOR 20     /* beta = cost_ms / 20      */

#define NGX_HTTP_CACHE_TURBO_AT_COST_STRONG_MS 30     /* expensive-regen gate     */
#define NGX_HTTP_CACHE_TURBO_AT_COST_MOD_MS    10     /* moderate-regen gate      */
#define NGX_HTTP_CACHE_TURBO_AT_MISSES_FLOOR   100    /* min misses/window + the
                                                       * min hits+misses to decide */
#define NGX_HTTP_CACHE_TURBO_AT_HIT_RATE_CAP   95     /* hit-rate < 95% (percent) */
#define NGX_HTTP_CACHE_TURBO_AT_CHURN_CAP      2      /* refreshes/misses > 2 → no */

/* Load-adaptive autotune (v4-4). Folded into cache_turbo_autotune on: when the
 * same cost/hit-rate verdict that drives beta says the backend is under load,
 * the zone also publishes a LOAD FACTOR (×1000, 1000 = baseline). The request
 * path widens two knobs by it — the serveable STALE window (not the fresh
 * window: the freshness contract is unchanged) and the single-flight lock_ttl —
 * so a slow/overwhelmed origin is shielded by serving stale longer and
 * collapsing more requests onto one regen. Snaps back to 1000 the first window
 * load clears. The factor is mapped from avg regen cost: AT_LOAD_PER_MS per ms
 * (so 1× at AT_COST_MOD_MS, the same moderate-load gate beta uses) and capped at
 * AT_LOAD_MAX (= a hard ≤4× ceiling on both widenings). */
#define NGX_HTTP_CACHE_TURBO_AT_LOAD_BASE      1000   /* 1.0 ×1000 (no widening)  */
#define NGX_HTTP_CACHE_TURBO_AT_LOAD_MAX       4000   /* 4.0 ×1000 (widening cap) */
#define NGX_HTTP_CACHE_TURBO_AT_LOAD_PER_MS    100    /* load = cost_ms × 100     */

/* Fixed autotune recompute cadence (seconds) when cache_turbo_autotune is on. */
#define NGX_HTTP_CACHE_TURBO_AT_INTERVAL       30

/* A preset band: the default value for each preset-controlled knob, plus the
 * [beta_min, beta_max] window the live autotune (v4-3) may move beta within for
 * this preset. The autotune computes a cost-derived target clamped to the global
 * [BETA_MIN, BETA_MAX]; the request path then re-clamps it to this band so e.g. a
 * conservative location never autotunes as hot as an aggressive one. */
typedef struct {
    time_t      valid;       /* fresh TTL (seconds)        */
    ngx_int_t   beta;        /* SWR aggressiveness, /1000  */
    time_t      lock_ttl;    /* single-flight lock window  */
    ngx_int_t   stale_mult;  /* stale window multiplier    */
    ngx_int_t   beta_min;    /* autotune lower clamp /1000 */
    ngx_int_t   beta_max;    /* autotune upper clamp /1000 */
    ngx_int_t   min_uses;    /* cold misses before storing */
} ngx_http_cache_turbo_band_t;


/*
 * One cached object living in the shared-memory slab. The node key is the
 * 32-byte hash of the cache key; the variable-length body (headers + payload,
 * serialised) is slab-allocated separately and pointed to by data/len.
 */

/* P6 circuit-breaker states (D-5: scope is PER-ZONE -- the shm zone is already
 * the accounting unit for autotune and stats, and a per-upstream breaker would
 * need new keying for no proven gain).
 *
 * ⚠ CLOSED == 0 is load-bearing, for the same reason NODE_ENTRY == 0 and
 * SEG_PROBATION == 0 are: a zone that is zeroed -- at init, or by accident --
 * must read as "breaker not tripped", which is the SAFE direction (traffic
 * flows to origin as if the feature were off). A silent flip of these values
 * would make a fresh zone come up OPEN and serve nothing but stale bodies and
 * 503s until the first probe. ci/tests/unit/extract_shm.sh pins all three. */
#define NGX_HTTP_CACHE_TURBO_BREAKER_CLOSED     0  /* origin believed healthy  */
#define NGX_HTTP_CACHE_TURBO_BREAKER_OPEN       1  /* origin dead: do not call */
#define NGX_HTTP_CACHE_TURBO_BREAKER_HALF_OPEN  2  /* one probe in flight      */

/*
 * P6/O4.3-c -- breaker_state is a PACKED word: [ generation | state ].
 *
 * The state alone is not enough to identify a LEASE. Publishing HALF_OPEN and
 * stamping the lease were two separate stores, and resolving it was a CAS on
 * the state enum only, which left two ABA holes (Codex review, PR #135):
 *
 *   - a worker could observe HALF_OPEN paired with the PREVIOUS lease's stamp
 *     -- necessarily old, zero on the first lease -- read it as abandoned, and
 *     reclaim a lease that was merely mid-publication; and
 *   - a probe descheduled after validating its token could have its
 *     HALF_OPEN -> CLOSED CAS land against a REPLACEMENT lease's generation,
 *     closing a breaker only the stale probe ever tested.
 *
 * Folding a generation counter into the same atomic word closes both: every
 * promotion bumps it, and every reclaim and resolution CASes the whole word, so
 * a transition belonging to a superseded lease cannot succeed. The generation
 * IS the lease token handed to the promoted request -- breaker_probe stays
 * only as the lease DEADLINE, never as identity.
 *
 * ⚠ CLOSED == 0 and generation 0 make a zeroed word read CLOSED, preserving the
 * fail-safe direction documented above. The generation is deliberately allowed
 * to wrap: at one promotion per open window it cannot realistically reach 2^62,
 * and a wrap is harmless anyway -- it would have to coincide exactly with an
 * outcome in flight from 2^62 leases ago.
 *
 * Pinned by ci/tests/unit/extract_shm.sh and the ABA tests in test_shm_state.c.
 */
#define NGX_HTTP_CACHE_TURBO_BREAKER_STATE_BITS  2
#define NGX_HTTP_CACHE_TURBO_BREAKER_STATE_MASK \
    ((ngx_uint_t) ((1U << NGX_HTTP_CACHE_TURBO_BREAKER_STATE_BITS) - 1))

#define ngx_http_cache_turbo_brk_state(w) \
    ((ngx_uint_t) (w) & NGX_HTTP_CACHE_TURBO_BREAKER_STATE_MASK)
#define ngx_http_cache_turbo_brk_gen(w) \
    ((ngx_uint_t) (w) >> NGX_HTTP_CACHE_TURBO_BREAKER_STATE_BITS)
#define ngx_http_cache_turbo_brk_pack(gen, st)                                \
    (((ngx_uint_t) (gen) << NGX_HTTP_CACHE_TURBO_BREAKER_STATE_BITS)          \
     | ((ngx_uint_t) (st) & NGX_HTTP_CACHE_TURBO_BREAKER_STATE_MASK))

/*
 * P6/O4.4-h -- breaker_probe is a PACKED word too: [ generation | stamp ].
 *
 * The generation in breaker_state made every TRANSITION generation-safe, but
 * the lease DEADLINE stayed a bare stamp in its own field, and nothing tied the
 * two together. The promotion CASes the state word to generation N and then
 * stores the stamp, so a reader could load generation N (current, therefore its
 * reclaim CAS succeeds) paired with generation N-1's long-expired stamp, and
 * reclaim a lease milliseconds old -- admitting the second concurrent probe the
 * breaker exists to prevent. The `stamp != 0` guard covered only the very first
 * lease of a zeroed zone, where there is no previous stamp to mispair with.
 *
 * ⚠ The in-code comment that claimed such a reader "is testing against
 * generation N-1 and loses" was WRONG: it loaded N. Do not restore that
 * reasoning.
 *
 * ⚠ Reversing the two stores does NOT fix this, which is why the stamp is
 * packed rather than merely re-ordered: with a bare stamp, two promoters racing
 * the same word both write their own `now`, and a later reader cannot tell
 * whose lease a stamp belongs to. The generation must travel WITH the stamp in
 * one atomically-published word so the reclaim test can demand that the
 * deadline it is about to act on belongs to the generation it observed.
 *
 * Publication order is deliberately probe-word FIRST, then the state CAS. A
 * probe word whose generation runs AHEAD of the state word is inert by
 * construction -- the reclaim branch runs only in HALF_OPEN and requires the
 * generations to match -- so a promoter that publishes and then LOSES the state
 * CAS leaves nothing visible behind. Publishing after the CAS would recreate
 * the very window this closes.
 *
 * The stamp is seconds RELATIVE to breaker_epoch, not an absolute epoch stamp:
 * an absolute stamp needs 31+ bits and cannot share a 32-bit ngx_atomic_t with
 * a usable generation. ngx_atomic_t is 32-bit on several targets in nginx's own
 * ngx_atomic.h, so the split is derived from its actual width rather than
 * assumed to be 64.
 *
 * ⚠ Generation 0 stays the NO_PROBE sentinel in the MASKED field as well: the
 * promotion skips a masked generation of 0 exactly as it skips a full one, so
 * no live lease is ever identified by 0 on either width. Aliasing needs a full
 * wrap of the masked field (2^PROBE_GEN_BITS - 1 promotions, since generation
 * 0 is skipped) to land inside one lease window -- see H-2's resolution
 * above for why that period must still be made unreachable rather than
 * merely large.
 *
 * Pinned by test_breaker_fresh_lease_not_reclaimable_via_old_stamp() and
 * ci/tests/unit/check_constants.sh (H-4: NOT extract_shm.sh, which slices
 * function bodies, not these macros -- check_constants.sh is the one that
 * diffs mirrored constant VALUES against this header).
 */
#define NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_WORD_BITS \
    ((ngx_uint_t) (sizeof(ngx_atomic_t) * 8))

/* Stamp width: 32 bits of relative seconds on a 64-bit atomic (~136 years,
 * i.e. never wraps in a process lifetime), which leaves 32 bits of
 * generation -- a masked-generation wrap period of 2^32 - 1 promotions
 * (generation 0 is skipped as the NO_PROBE sentinel, see the pack-site
 * comment below), unreachable by continuous flapping in any realistic
 * uptime.
 *
 * ⚠ The narrow (32-bit atomic) layout DOES wrap in ordinary operation. Its
 * old 20/12 split gave a masked-generation wrap period of 2^12 - 1 = 4095
 * promotions -- roughly 34 hours of continuous open/probe/reopen flapping at
 * `open_for 30s` -- which is the H-2 ABA producer: a promoter parked between
 * the publication CAS and the state CAS across a full masked-generation wrap
 * finds its expectation coincidentally matching, publishing a probe word for
 * the WRONG live generation. No split of a 32-bit word gives both a stamp
 * field wide enough to measure a BREAKER_PROBE_LEASE-aged lease without
 * wrapping (see the modular-age note above) and a generation field wide
 * enough to put a flapping-driven wrap out of reach: shrinking the stamp
 * to buy generation bits only trades one wrap hazard for a faster one. This
 * module's own package builds are 64-bit, so rather than ship a layout with
 * a reachable wedge, the narrow layout is rejected outright -- see the
 * #error below. If a 32-bit target is ever genuinely required, closing H-2
 * there needs a wider piece of state than one ngx_atomic_t (e.g. a separate
 * monotonic promotion-sequence field), not a different bit split. */
/* H-1: an undefined NGX_PTR_SIZE must be a hard build error here, not a
 * silent fallback to the narrow layout. NGX_PTR_SIZE normally comes from
 * nginx's own objs/ngx_auto_config.h; any build that reaches this point
 * without it (e.g. a unit-test harness that forgot to define it) would
 * otherwise silently compile the WRONG packed-word layout -- exactly the
 * defect this #error replaces. See the mirrored guard in
 * ci/tests/unit/test_shm_state.c and the definition site in
 * ci/tests/unit/ngx_shim_shm.h. */
#if !defined(NGX_PTR_SIZE)
#error "NGX_PTR_SIZE is not defined -- cannot select the breaker probe word layout"
#endif

/* H-2/O4.4-j: the 32-bit-atomic (NGX_PTR_SIZE < 8) layout is rejected
 * outright rather than built with a reachable masked-generation ABA wrap.
 * See the block comment above for why no bit split fixes this on a single
 * 32-bit word. */
#if (NGX_PTR_SIZE >= 8)
#define NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_STAMP_BITS  32
#else
#error "the 32-bit breaker probe word layout has a reachable H-2 masked-" \
       "generation ABA wrap (~34h of continuous flapping); this module " \
       "ships 64-bit builds only -- see the packed-probe layout comment " \
       "in ngx_http_cache_turbo_module.h"
#endif

#define NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_STAMP_MASK                         \
    ((ngx_uint_t) ((((ngx_uint_t) 1)                                          \
                    << NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_STAMP_BITS) - 1))
#define NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_GEN_BITS                           \
    (NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_WORD_BITS                             \
     - NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_STAMP_BITS)
#define NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_GEN_MASK                           \
    ((ngx_uint_t) ((((ngx_uint_t) 1)                                          \
                    << NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_GEN_BITS) - 1))

#define ngx_http_cache_turbo_brk_probe_stamp(w) \
    ((ngx_uint_t) (w) & NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_STAMP_MASK)
#define ngx_http_cache_turbo_brk_probe_gen(w)                                 \
    (((ngx_uint_t) (w) >> NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_STAMP_BITS)      \
     & NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_GEN_MASK)
#define ngx_http_cache_turbo_brk_probe_pack(gen, stamp)                       \
    ((((ngx_uint_t) (gen) & NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_GEN_MASK)      \
      << NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_STAMP_BITS)                       \
     | ((ngx_uint_t) (stamp)                                                  \
        & NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_STAMP_MASK))

/* H-2/O4.4-j: the #error above gates on NGX_PTR_SIZE, but the hazard is a
 * function of the ATOMIC width -- PROBE_WORD_BITS is sizeof(ngx_atomic_t), not
 * sizeof(void *). On every target this module ships they agree, and on the
 * usual ILP32/LP64 models they always do. They are not the same thing though:
 * a model with 64-bit pointers and a 32-bit long (x32) would satisfy the
 * NGX_PTR_SIZE >= 8 gate while giving a 32-bit word, so STAMP_BITS 32 would
 * leave GEN_BITS 0 and GEN_MASK 0 -- every generation would read as NO_PROBE
 * and the breaker would never promote a probe at all. That is worse than the
 * wedge the gate exists to prevent, and #if cannot see sizeof, so it is
 * asserted at compile time here instead.
 *
 * A negative width is the standard trick: the array is well-formed only while
 * the generation field has room left. Keep this beside the pack macros -- it is
 * the only check tying the #if-selected split back to the real atomic. */
typedef char ngx_http_cache_turbo_brk_probe_layout_assert
    [(NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_WORD_BITS
      > NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_STAMP_BITS) ? 1 : -1];

/* P6/O4.3 serve-path actions, the verdict of
 * ngx_http_cache_turbo_breaker_action(). PASS is the only one that lets the
 * request reach the origin.
 *
 * ⚠ PASS == 0 is load-bearing, exactly like BREAKER_CLOSED == 0 above: the safe
 * direction for a zeroed or accidentally-defaulted value is "the breaker does
 * not interfere". A silent flip would make the fall-through case start serving
 * stale bodies or 503s. */
/* P6/O4.3: "no probe lease held". 0 is safe as the sentinel because the token
 * is a GENERATION and the promotion path skips generation 0 explicitly (see the
 * packed-word block above), so no live lease is ever identified by 0. The
 * earlier stamp-based token relied on the probe stamp's zeroed-zone value for
 * the same guarantee; that rationale is obsolete, the sentinel is not. */
#define NGX_HTTP_CACHE_TURBO_BREAKER_NO_PROBE  0

/*
 * P6/O4.4-a -- how long a promoted probe OWNS its lease, deliberately NOT
 * breaker_open.
 *
 * These are two unrelated durations that an earlier revision conflated.
 * breaker_open answers "how long does OPEN wait before letting one probe
 * through"; this answers "how long may that probe take before we assume its
 * worker died and admit a replacement". Reclaiming on breaker_open makes any
 * probe SLOWER than breaker_open get its lease reclaimed while still in flight
 * -- its healthy response then arrives holding a superseded generation and is
 * correctly discarded, so the breaker trips and can never close again.
 *
 * ⚠ The shipped `breaker_open 30s` default sat squarely inside that hazard:
 * nginx's proxy_connect_timeout and proxy_read_timeout both default to 60s, so
 * an origin that is merely SLOW -- not dead -- could never close the breaker.
 *
 * 300s is chosen to clear the ~120s that those two defaults imply for a normal
 * origin attempt, with margin, while still bounding a genuinely abandoned lease
 * to something an operator would wait out.
 *
 * ⚠ 300s is NOT a proof of safety, and no finite constant here could be.
 * proxy_read_timeout is measured between successive READS, not across the whole
 * response, and proxy_next_upstream_tries/_timeout default to unlimited -- so
 * time-to-response-headers is genuinely unbounded. A probe slower than this
 * lease still gets superseded and its healthy outcome still discarded; it is
 * re-probed every lease rather than never, so the breaker recovers late instead
 * of wedging. Closing that class needs an enforced total time-to-header
 * deadline on the probe, below this lease. Tracked as O4.4-g in memory
 * issues.md. This constant widens the safe band; it does not end the problem.
 *
 * It is
 * INTERNAL on purpose (decision, 2026-07-29): a directive would add a third
 * argument to _breaker_state() and a knob with no tuning signal behind it.
 * The lease is a liveness backstop, not a policy -- the ordinary path resolves
 * it in _breaker_record() the moment the probe reports, whatever this value is.
 *
 * Pinned by test_breaker_probe_lease_is_independent_of_open().
 */
#define NGX_HTTP_CACHE_TURBO_BREAKER_PROBE_LEASE  300

#define NGX_HTTP_CACHE_TURBO_BRK_ACT_PASS   0  /* fall through, ordinary request */
#define NGX_HTTP_CACHE_TURBO_BRK_ACT_SERVE  1  /* serve the fallback body        */
#define NGX_HTTP_CACHE_TURBO_BRK_ACT_FAIL   2  /* 503 + Retry-After, no origin   */
/*
 * P6/O4.3-c: the promoted probe. DISTINCT from PASS because the probe must go
 * to the origin DIRECTLY -- PASS merely falls through, and everything after the
 * breaker gate (min_uses, claim(), the cross-node NX lock, cold_wait()) can
 * park the request and resume it. On resume the L1 fresh/stale and L2-HIT
 * returns sit BEFORE the gate, and brk_consulted keeps the gate from running a
 * second time, so the lease holder could be answered from a peer's fill without
 * ever contacting the origin -- burning the lease, recording no outcome
 * (_serve() sets ctx->served, and the header filter skips _breaker_record()),
 * and leaving the breaker HALF_OPEN until the lease expires.
 *
 * Collapsing this back into PASS reintroduces exactly that (Codex F2, PR #135).
 */
#define NGX_HTTP_CACHE_TURBO_BRK_ACT_PROBE  3  /* the probe: origin, directly    */

/* protected_pct bounds for cache_turbo_scan_resistant (range-checked setter,
 * NOT ngx_conf_set_num_slot -- a literal 0 must be a config error, not a
 * silently-coerced default. See H5/min_uses for the trap this avoids). */
#define NGX_HTTP_CACHE_TURBO_PROTECTED_PCT_MIN      1
#define NGX_HTTP_CACHE_TURBO_PROTECTED_PCT_MAX     99
#define NGX_HTTP_CACHE_TURBO_PROTECTED_PCT_DEFAULT 80

/* cache_turbo_warm_max bounds (P5-2-p0). DEFAULT matches the previous
 * hardcoded NGX_HTTP_CACHE_TURBO_WARM_MAX cap byte-for-byte, so behaviour is
 * unchanged unless an operator opts in. CEILING keeps a single admin warm
 * request well under nginx's subrequest-depth limit even when an operator
 * dials the cap all the way up -- see the directive handler for why this is
 * a hand range-check rather than a bare ngx_conf_set_num_slot. */
#define NGX_HTTP_CACHE_TURBO_WARM_MAX_DEFAULT   32
#define NGX_HTTP_CACHE_TURBO_WARM_MAX_CEILING  4096

typedef struct {
    ngx_rbtree_node_t        node;       /* node.key = first 8 bytes of the
                                          * 32-byte key hash (C4); NOT the
                                          * 32-bit crc32 short hash -- see
                                          * ngx_http_cache_turbo_shm_key64()
                                          * in shm.c                       */
    u_char                   key[32];    /* full key hash, collision guard */

    /* What this node holds; see NGX_HTTP_CACHE_TURBO_NODE_* above. ENTRY is 0 so
     * a node zeroed by accident reads as ENTRY -- which every serve branch then
     * rejects on its own `len > 0` test, i.e. the safe direction. */
    ngx_uint_t               kind;

    u_char                  *data;       /* blob bytes; CT_BLOBREF() header
                                          * sits immediately before, slab alloc */
    size_t                   len;

    time_t                   fresh_until;   /* < now  => stale              */
    time_t                   stale_until;   /* < now  => expired/evict      */

    ngx_uint_t               refreshing;    /* a single-flight regen in air */

    /* CTXRDR-ADOPT-LEASE: identity of the request that currently holds the
     * single-flight lease, as a zone-wide never-reused token (see sh->owner_seq).
     * Assigned under the zone mutex by claim() every time it returns
     * CLAIM_WINNER, including the TAKEOVER case where the lease is handed from a
     * dead/expired winner to a new one.
     *
     * ⚠ WHY THIS EXISTS. `refreshing` + `refresh_lock_until` say a lease is live;
     * they do NOT say whose. claim() deliberately re-leases an expired stub to a
     * different request, so a request that once owned this key cannot conclude
     * from its own request-local state that it still does. Without an identity
     * here, unstub() matched on kind + refreshing alone and a late-finishing
     * LOSER could clear the CURRENT winner's live lease -- breaking single-flight
     * and stampeding the origin exactly during the origin slowness that opened
     * the window. Compare this token, never the flags alone.
     *
     * 0 = no lease (never claimed, or released). owner_seq starts at 1 so a
     * zeroed node can never collide with a live token. */
    uint64_t                 refresh_owner;

    time_t                   refresh_lock_until; /* hard single-flight guard:
                                              * while now < this, ALL readers
                                              * serve stale and skip the dice;
                                              * only the claimer regenerates.
                                              * Self-heals if a refresh dies. */

    /* min_uses (v15) miss counter. A COUNTER node tracks how many times a key has
     * cold-missed without yet being cached, so cache_turbo_min_uses N can defer
     * the first store until the key has been requested N times (don't cache
     * one-hit-wonders). Irrelevant once the node becomes an ENTRY; left untouched
     * then.
     *
     * ⚠ A COUNTER with miss_count > 0 carries state the owner never asked to
     * discard: shm_unstub() must NOT free it (that would silently reset the
     * min_uses threshold). See the predicate there. */
    ngx_uint_t               miss_count;

    /* L2 negative memo (L13). When cache_turbo_l2_negative_ttl is set, an L2 GET
     * that DEFINITIVELY missed stamps `now + l2_negative_ttl` here, and subsequent
     * cold requests for the same key skip the L2 round-trip until it expires.
     * Rides on the same COUNTER node as miss_count above, so a memo costs no extra
     * allocation when min_uses already made one. 0 = no memo. Cleared on store
     * (an ENTRY never consults L2).
     *
     * ⚠ ONLY a definitive miss may arm this -- never a transport failure. An L2
     * outage that armed memos would suppress the very GETs that notice recovery
     * (fail-slow amplification for up to l2_negative_ttl past recovery), and an
     * alloc failure on a real L2 HIT would arm a memo asserting the key is ABSENT.
     * The adapters therefore distinguish the two: NGX_DECLINED = definitive miss
     * (arms), NGX_ERROR = transport failure (must not arm). See l2_result.
     *
     * ⚠ The memo survives the single-flight that armed it. It is NOT cleared when
     * a COUNTER becomes a stub (refreshing = 1) -- doing so destroyed the memo
     * before any later request could read it, which is why the window used to
     * collapse to ~1 request (CodeRabbit CR-A on PR #77).
     *
     * COHERENCE: this is a bounded-staleness memo, NOT an invalidating one --
     * nothing tells this node that a PEER stored the key during the window. The
     * TTL is the entire coherence story, which is why it is off by default and
     * capped at NGX_HTTP_CACHE_TURBO_L2_NEG_TTL_MAX. Worst case, a multi-node
     * L2 hit is missed for up to l2_negative_ttl seconds and the request goes to
     * origin instead -- a performance loss, never a correctness one (a stale
     * body is never served from a memo; the memo holds no body at all). */
    time_t                   l2_neg_until;

    /* PERF (P1): coarse last-access stamp (1s granularity, ngx_time). The true-LRU
     * head-splice on every HIT is a WRITE to the shared LRU list under
     * shpool->mutex — on a hot key that serializes all readers on the same cache
     * lines. We re-splice only when now - last_access >= 1, so a key hammered many
     * times per second splices at most once/second. Eviction is best-effort/
     * approximate anyway (shm.c), so an LRU that is at most ~1s stale is harmless.
     * 0 = never spliced (fresh node); the first HIT always splices. */
    time_t                   last_access;

    /* S8 (scan-resistant segmented LRU). Which LRU queue this node's `lru` link
     * is currently threaded on: SEG_PROBATION => &sh->lru, SEG_PROTECTED =>
     * &sh->lru_protected. Exactly one, always -- every detach/insert pair must
     * keep this field and the actual linkage in agreement, or eviction walks a
     * node that is not on the queue it is being taken from.
     *
     * ⚠ PROBATION is 0 for the same reason NODE_ENTRY is 0: a node zeroed by
     * accident must read as probation, i.e. the EVICTABLE direction. Inverting
     * this would make a corrupted node un-evictable and leak the zone. Do NOT
     * invert it.
     *
     * When cache_turbo_scan_resistant is off (the default) nothing ever sets
     * this to PROTECTED, sh->lru_protected stays empty, and every path degrades
     * to exactly the flat single-queue LRU that shipped before S8. */
    ngx_uint_t               seg;

    /* S8: has this node been touched (accessed) at least once since it was
     * stored? A store leaves it 0, the first HIT sets it, and the SECOND hit is
     * therefore the one that promotes. Cheaper and less racy than a hit counter
     * -- we only ever need "have we seen this before", not how many times.
     *
     * Reset to 0 on a refresh store: a refreshed body is a new representation,
     * so it re-earns protection rather than inheriting it. */
    ngx_uint_t               promotable;

    /* S231-EVICT-BLIND: second-chance bit for a live-SIE entry evicted while
     * the breaker is OPEN. evict_one() does not skip a live-SIE candidate
     * outright -- during an outage every resident entry can be SIE-live, and
     * an unconditional skip finds alloc_evict() no victim at all, wedging
     * every store behind a mutex-held spin (the same hang hazard evict_one()
     * already guards against for the two-queue walk above). Instead a
     * live-SIE candidate is passed over ONCE: this bit is set and the walk
     * moves to the next tail candidate. A candidate whose bit is ALREADY set
     * is evictable on sight, so the walk is still bounded by n_entries and
     * still terminates. 0 = not yet spared (fresh node, or spared bit
     * consumed by a prior eviction pass and the node re-inserted since). */
    unsigned                 sie_spared:1;

    /* COR-5(b): the auto-Vary variant-index SADD for THIS variant was DROPPED
     * before the wire (armed S231 connect-backoff, failed connect, or an
     * alloc failure) at store time. The object is in L1 and serves normally,
     * but the per-base index set does not list it -- so a later PURGE of the
     * base enumerates the set via SMEMBERS, does not see this variant, and
     * reports success while this node keeps serving a stale representation
     * until its own TTL.
     *
     * Self-heal: the next L1 hit on this node re-issues the SADD (still
     * fire-and-forget, still off the blocking path -- see access_l1) and
     * clears this bit once the op reaches the transport. A re-issue that is
     * dropped again leaves the bit set, so the next hit retries; during a
     * long L2 outage every attempt short-circuits on the backoff check
     * without a connect(), so the retry costs a function call.
     *
     * MEMORY BOUND: one bit inside an already-allocated node. There is no
     * pending list and no per-key allocation, so a multi-hour L2 outage adds
     * exactly zero bytes to the zone -- the pending set can never exceed the
     * number of resident nodes, and a node's pending state is freed with the
     * node on eviction or expiry. That bound is the reason this lives here
     * rather than in a retry queue. */
    unsigned                 varidx_pending:1;

    ngx_queue_t              lru;           /* LRU list linkage             */
} ngx_http_cache_turbo_node_t;


/* Shared-memory zone state: rbtree of cached objects + LRU + stats. */
typedef struct {
    ngx_rbtree_t             rbtree;
    ngx_rbtree_node_t        sentinel;

    /* S8: the PROBATION queue. Named `lru` still because when
     * cache_turbo_scan_resistant is off this is the ONLY populated queue and
     * every node lives here, exactly as before S8. */
    ngx_queue_t              lru;

    /* S8: the PROTECTED queue, and how many nodes are on it. Empty and 0
     * respectively unless scan resistance is enabled.
     *
     * ⚠ evict_one() must consult BOTH: probation tail first (that ordering IS
     * the scan resistance), falling through to the protected tail when
     * probation is empty. Returning 0 while this queue is non-empty makes
     * alloc_evict() give up on a zone that still has reclaimable entries;
     * returning non-zero without evicting makes it spin forever holding the
     * mutex. See the hang test in ci/tests/unit/test_shm_state.c.
     *
     * n_protected is maintained under shpool->mutex alongside the linkage, so
     * it is a plain ngx_uint_t rather than an atomic -- never read outside the
     * lock. */
    ngx_queue_t              lru_protected;
    ngx_uint_t               n_protected;
    ngx_uint_t               n_entries;     /* nodes on BOTH queues combined */

    ngx_atomic_t             hits;
    ngx_atomic_t             misses;
    ngx_atomic_t             stale_serves;
    ngx_atomic_t             refreshes;
    ngx_atomic_t             evictions;

    /* C3: live count of L1 auto-Vary marker nodes (kind ==
     * NGX_HTTP_CACHE_TURBO_NODE_MARKER) currently resident in THIS zone's
     * stripe -- a presence gauge, not a lifetime counter. Bumped once, under
     * the zone mutex, by ngx_http_cache_turbo_shm_store_marker() the moment it
     * creates a brand-new marker node (never on a refresh of an existing one).
     * Dropped, also lock-held, by every site that can free a node regardless
     * of kind (ngx_http_cache_turbo_shm_evict_one()'s two take sites,
     * ngx_http_cache_turbo_shm_drop_locked() shared by purge_key/purge_all) --
     * each checks `ctn->kind == NGX_HTTP_CACHE_TURBO_NODE_MARKER` before
     * freeing and decrements only then. The fourth and last node-free site in
     * the module (the COUNTER-stub unstub reclaim in
     * ngx_http_cache_turbo_shm_resolve_miss()) is gated on
     * `kind == NGX_HTTP_CACHE_TURBO_NODE_COUNTER`, which provably excludes a
     * MARKER node, so it needs no decrement. Read (unlocked, plain load like
     * every other atomic in this block) by the auto-Vary probe gate in
     * access.c: `markers == 0` proves the zone holds no marker anywhere, so
     * ngx_http_cache_turbo_vary_apply()'s lock-held L1 lookup is guaranteed to
     * find nothing and can be skipped -- see access_l1()'s call site for the
     * exact side effects that skip must still replicate.
     *
     * Deliberately conservative in one direction only: over-count is the safe
     * failure (the gate simply stops firing, falling back to the pre-C3
     * always-probe behaviour) and this field can never under-count, because
     * every increment and every decrement runs under the SAME zone-mutex hold
     * as the node mutation it accounts for -- see _shm_store_marker()'s single
     * lock/unlock pair, which checks-then-creates-then-tags atomically rather
     * than across two separate lock acquisitions (a node evicted and
     * recreated between two such acquisitions would otherwise be missed). */
    ngx_atomic_t             markers;

    /* P3-7: zone-wide count of background-refresh (SWR bg-update) subrequests
     * currently in flight, gated by cache_turbo_background_update_max. Per-key
     * single-flight (refreshing/refresh_lock_until above) caps regens for ONE
     * key; nothing capped the SUM across keys, so a synchronized mass-expiry
     * (deploy, mass purge, restart touching a shared TTL) could fire one
     * background subrequest per stale key simultaneously — thousands of
     * concurrent origin requests, invisible to per-key metrics because each
     * key is still correctly single-flighted.
     *
     * ⚠ Incremented in ngx_http_cache_turbo_warm_one() only after the cap
     * check passes and ngx_http_subrequest() has posted the subrequest.
     * Decremented ONLY by a pool cleanup registered on the subrequest's OWN
     * pool (sr->pool), never by a return-value check at the call site: once
     * ngx_http_subrequest() succeeds, warm_one() has several early-return
     * failure arms (anonymize failure, ctx alloc failure) that leave the
     * subrequest posted and running while returning NGX_ERROR to the caller.
     * A decrement keyed to warm_one()'s return value would never fire on
     * those arms and would leak the counter — permanently wedging background
     * refresh for the whole zone once bg_inflight saturates
     * background_update_max. The cleanup fires exactly once, whether the
     * subrequest finishes cleanly or one of those arms tears it down early. */
    ngx_atomic_t             bg_inflight;

    /* L2 (Redis or memcached) outcome counters (v12): incremented on an L1
     * miss that consulted L2 — l2_hits when L2 held the object (filled L1),
     * l2_misses when it did not (went to origin). Zero when no L2 is
     * configured. */
    ngx_atomic_t             l2_hits;
    ngx_atomic_t             l2_misses;

    /* Cold-miss single-flight (v10): bumped once when a request first enters the
     * wait loop (a coalesced cold-miss that did NOT go to origin). Zero when
     * cache_turbo_lock is off. Observability for the single-flight working. */
    ngx_atomic_t             lock_waits;

    /* CTXRDR-ADOPT-LEASE: monotonic source of single-flight owner tokens for
     * this zone (node->refresh_owner). Pre-incremented under shpool->mutex by
     * claim(), so the first token issued is 1 and 0 is always "no owner" --
     * a zeroed or freshly-slab-allocated node can never impersonate a holder.
     *
     * ⚠ NOT an ngx_atomic_t and must not become one: it is only ever read and
     * written while holding the zone mutex, together with the refreshing /
     * refresh_lock_until fields it identifies. Making it atomic would invite a
     * lock-free bump that could hand two requests the same token.
     *
     * uint64_t, so it cannot wrap in any real deployment: at a sustained one
     * million cold-miss claims per second it takes ~584,000 years to exhaust.
     * "Never reused" is what makes a stale token safe to compare -- an ABA on
     * this field would resurrect exactly the defect it was added to close. */
    uint64_t                 owner_seq;

    /* min_uses (v15): bumped once per cold miss that was sent to the origin
     * WITHOUT storing because the key is still below cache_turbo_min_uses. Zero
     * when min_uses is 1 (the default — feature off). Observability for the
     * "don't cache one-hit-wonders" gate. */
    ngx_atomic_t             min_uses_skips;

    /* L13: bumped once per L2 GET that a negative memo made unnecessary. Zero
     * when cache_turbo_l2_negative_ttl is 0 (the default — feature off). This
     * is the payoff metric: each unit is one L2 round-trip not taken. Compare
     * against l2_hits to size the window — a memo that is suppressing hits
     * (rising l2_neg_skips with falling l2_hits) is set too long. */
    ngx_atomic_t             l2_neg_skips;

    /* Requests sent to origin because a cache_turbo_bypass predicate tripped or
     * a CMS backend preset auto-classified them as dynamic. Also counted in
     * misses (they reached origin); bypasses isolates the "skipped on purpose"
     * subset for $cache_turbo_status / Prometheus. */
    ngx_atomic_t             bypasses;

    /* P0-1: ngx_http_cache_turbo_response_cacheable()'s reason_out. NONE (0)
     * only when the function itself returns 1 -- a caller must not read a
     * stale/uninitialised reason after a 1 return. */
#define NGX_HTTP_CACHE_TURBO_REFUSE_NONE            0
#define NGX_HTTP_CACHE_TURBO_REFUSE_SET_COOKIE      1
#define NGX_HTTP_CACHE_TURBO_REFUSE_AUTHORIZATION   2
#define NGX_HTTP_CACHE_TURBO_REFUSE_CACHE_CONTROL   3

    /* P0-1: per-reason store-refusal counters. All eight fire ONLY on the
     * capture (store) decision path in the header filter -- never on a HIT,
     * so they add no work to the serve path. Each isolates one arm of the
     * "do not store" gate chain (filters.c capture condition +
     * response_cacheable() + classify_vary()) so an operator sees WHY the
     * hit ratio is low instead of a bare 0%. A response can trip more than
     * one reason in principle (e.g. Set-Cookie AND pre-encoded); each arm
     * that observes its own condition bumps independently, so these do NOT
     * sum to (misses - hits) and must not be read as mutually exclusive. */
    ngx_atomic_t             refuse_set_cookie;    /* response sets Set-Cookie */
    ngx_atomic_t             refuse_encoded;       /* response pre-encoded (Content-Encoding) */
    ngx_atomic_t             refuse_vary_unsafe;   /* unknown/non-whitelisted Vary axis, or Vary: * */
    ngx_atomic_t             refuse_authorization; /* request carried Authorization */
    ngx_atomic_t             refuse_cache_control; /* response Cache-Control/CDN-Cache-Control/
                                                     * Surrogate-Control veto (no-store/no-cache/
                                                     * private/max-age=0/s-maxage=0) */
    ngx_atomic_t             refuse_require_header;/* cache_turbo_require_header unmet/absent */
    ngx_atomic_t             refuse_partial;       /* 206 Partial Content */
    ngx_atomic_t             refuse_head;          /* HEAD request (never overwrites the GET entry) */

    /*
     * Live autotune state (v4-3). cost_sum_ms / cost_count accumulate the
     * wall-clock cost of every origin regeneration (request_time at the
     * origin→cache store), so their ratio is the average miss-cost the autotune
     * feeds on. autotuned_beta is the verdict the request path reads (×1000;
     * 0 = no verdict yet → fall back to the preset/explicit beta). autotune_next
     * throttles the recompute to once per interval per worker. The snap_* fields
     * are the counter values at the previous recompute so each tick works on the
     * delta over the last window (windowed, not lifetime-cumulative → it adapts
     * down as well as up). All mutated under shpool->mutex in the recompute.
     */
    ngx_atomic_t             cost_sum_ms;   /* Σ origin-regen request_time (ms) */
    ngx_atomic_t             cost_count;    /* number of origin regens measured */
    ngx_atomic_t             autotuned_beta;/* live verdict ×1000, 0 = none     */
    ngx_atomic_t             autotuned_load;/* v4-4 load factor ×1000, 0/1000   *
                                             * = baseline (no stale/lock widen) */
    ngx_atomic_t             autotune_next; /* next recompute (epoch seconds)   */
    ngx_atomic_uint_t        snap_hits;
    ngx_atomic_uint_t        snap_misses;
    ngx_atomic_uint_t        snap_refreshes;
    ngx_atomic_uint_t        snap_cost_sum;
    ngx_atomic_uint_t        snap_cost_count;

    /*
     * P6 circuit-breaker state (O4.1). Per-zone (D-5). Mutated ONLY by
     * ngx_http_cache_turbo_shm_breaker_state() / _record(). Every STATE
     * transition goes through ngx_atomic_cmp_set; the counters and timestamps
     * beside it are plain stores and fetch_adds (they are advisory -- see
     * below). Deliberately NO shpool->mutex anywhere. The breaker is
     * consulted on the request path before the origin connect, which is the
     * hottest possible read site; taking the zone mutex there would serialise
     * every request in the zone behind a lock whose other holders do slab
     * allocation and rbtree surgery. Lock-free also means the breaker adds no
     * new mutex ordering to reason about (the module already has one deadlock
     * class from nesting shpool->mutex under itself -- see the l1->store()
     * warning in memory issues.md), and no way for a worker killed mid-update
     * to leave the zone holding a lock nobody will release.
     *
     * ⚠ Lock-freedom does NOT by itself make the state machine liveness-safe.
     * A worker killed after being promoted to the probe leaves the breaker in
     * HALF_OPEN with nothing left to report the outcome, which would wedge it
     * permanently. breaker_probe exists to bound exactly that: the promotion
     * is a LEASE, and a stale one is reclaimed. See _breaker_state().
     *
     * ⚠ O4.4-a: that lease elapses after BREAKER_PROBE_LEASE, which is NOT
     * breaker_open. Bounding it by breaker_open instead reclaimed any probe
     * slower than breaker_open while it was still in flight, so a
     * slow-but-healthy origin could never close the breaker.
     *
     * The cost of that choice is that the fields are NOT mutually consistent
     * under concurrency, so nothing may read two of them and assume they
     * describe the same instant. Each transition is carried by a single CAS on
     * breaker_state, and every other field is either advisory (fails,
     * window_start) or written by the CAS winner alone (probe_at). opened_at is
     * deliberately PUBLISHED BEFORE the transition CAS by every racing writer,
     * not just the winner, so a worker that can observe OPEN can always observe
     * a deadline at least as new -- see the ordering notes in _breaker_record().
     *
     * ⚠ A reload does NOT reset any of this. _shm_init_zone() deliberately
     * inherits the live shm from the old cycle (`ctx->sh = octx->sh`), so a zone
     * that was OPEN before the reload is still OPEN after it, mid-window and
     * mid-lease. An earlier version of this comment claimed the opposite; the
     * zone is reused, not re-created.
     *
     * The consequence worth knowing (O4.4-d): breaker STATE is per-ZONE while
     * the directives that drive it are per-LOCATION, and during a reload the old
     * and new workers both run against this one machine with whatever policy
     * each was configured with. Failures counted under one location's threshold
     * satisfy another's, and a threshold change takes effect against a counter
     * accumulated under the previous one. Treat the zone, not the location, as
     * the failure domain.
     */
    ngx_atomic_t             breaker_state;        /* BREAKER_* above          */
    ngx_atomic_t             breaker_fails;        /* failures this window     */
    ngx_atomic_t             breaker_window_start; /* epoch s, window anchor   */
    ngx_atomic_t             breaker_opened_at;    /* epoch s the OPEN began   */
    ngx_atomic_t             breaker_probe;        /* O4.4-h packed
                                                    * [generation | stamp];
                                                    * stamp is seconds since
                                                    * breaker_epoch, lease
                                                    * elapses after
                                                    * BREAKER_PROBE_LEASE     */
    ngx_atomic_t             breaker_epoch;        /* O4.4-h epoch s the zone
                                                    * was initialised; anchor
                                                    * for the relative stamp
                                                    * above. Written once at
                                                    * init, never again -- a
                                                    * reload INHERITS it with
                                                    * the rest of the shm     */
    ngx_atomic_t             breaker_opens;        /* lifetime CLOSED→OPEN     */

    /* S7.1: production observability counters (NOT TEST_FAULTS-gated -- these
     * are permanent operator-facing fields, unlike the O4.4-i arming counters
     * below). Each counts SERVES -- responses actually delivered that way --
     * not arm/consult events; see the bump-site comments for why each site
     * was chosen over other plausible ones.
     *
     *   sie_serves      -- responses served from a stale-if-error snapshot
     *                      (ngx_http_cache_turbo_sie_rewrite() succeeding).
     *   breaker_serves  -- responses served from the breaker's armed fallback
     *                      while OPEN (the STALE-BREAKER serve, both the
     *                      only-if-cached and pre-origin-gate sites).
     *   origin_failures -- origin responses that fed the breaker as a
     *                      failure (ngx_http_cache_turbo_breaker_is_origin_failure()
     *                      true at the same site _breaker_record() is called). */
    ngx_atomic_t             sie_serves;
    ngx_atomic_t             breaker_serves;
    ngx_atomic_t             origin_failures;

    /* COR-5(b) variant-index self-heal observables. `varidx_drops` counts
     * index writes that never reached the transport at store time (each one
     * arms a node's varidx_pending bit); `varidx_reissues` counts re-issues a
     * later hit successfully handed to the transport. Two counters, not one:
     * the test's oracle must distinguish "the drop was detected" from "the
     * self-heal actually fired", and a combined counter would let a test pass
     * on detection alone with the index still short a variant.
     *
     * ⚠ ZONE-scoped, not process-global like the S231 backoff counters. The
     * runtime suite runs 4 workers with no request affinity, so the store and
     * the response that reports the counter routinely land in DIFFERENT
     * workers -- a per-worker counter reads 0 on the reporting worker and the
     * assertion goes vacuous. The state being observed (a node's pending bit)
     * is itself zone-scoped, so this is also the honest scope. */
    ngx_atomic_t             varidx_drops;
    ngx_atomic_t             varidx_reissues;

    /* L9: counts tag-index writes (tag_add / tag_add_many for
     * cache_turbo_tag) that never reached the transport at store time --
     * the same drop class as varidx_drops above, but for the purge-by-tag
     * index rather than the auto-Vary variant index. No self-heal exists
     * for this write yet (unlike varidx_pending), so there is only one
     * counter: this makes the drop OBSERVABLE (an operator/alert can see
     * a purge-by-tag is silently missing an object) without changing when
     * or whether the write itself happens. ZONE-scoped for the same
     * reason as varidx_drops -- the runtime suite has no request affinity
     * across its 4 workers.
     *
     * SILENT-INDEX-DROP(c): this counter is now READ by the purge-by-tag
     * reply, which reports "complete":false while it is non-zero. There is
     * deliberately NO tag_index_reissues companion: a re-issue is not
     * possible for tags (the tag set is a cache_turbo_tag complex value
     * evaluated against the ORIGIN RESPONSE in the body filter, so a later
     * cache hit has no upstream to re-derive it from and would index the
     * WRONG tags). The gap therefore never closes on its own, which is
     * exactly what the reply is reporting: once a tag write has been
     * dropped in this zone, no purge-by-tag in it can claim a complete
     * enumeration until the zone is reloaded. */
    ngx_atomic_t             tag_index_drops;

    /* TAG-CAP-SILENT-DROP: counts tags silently dropped from the tag INDEX
     * because a response named more than NGX_HTTP_CACHE_TURBO_MAX_TAGS
     * distinct tags (_body_filter_tag_split's cap, filters.c). This is a
     * DIFFERENT fault class from tag_index_drops above: tag_index_drops is
     * a transport failure (SADD never reached L2) for tags that WERE
     * selected; tag_cap_drops is tags that never got a chance to be
     * selected at all because the cap truncated the value first. Distinct
     * counter, not folded into tag_index_drops, so an operator can tell
     * "L2 was unreachable" (transient, fixed by retry/reload) from
     * "raise the cap or emit fewer tags" (a config/origin problem) apart
     * on the same admin/Prometheus surface.
     *
     * Same no-self-heal reasoning as tag_index_drops: the dropped tag is
     * never re-derived by a later cache hit, so once a response has hit
     * the cap, purge-by-tag on the truncated tag(s) can never claim a
     * complete enumeration for this zone until reload. Feeds the SAME
     * purge-by-tag "complete":false decision as tag_index_drops (see
     * admin.c's ?tag= handler and tag_purge_complete in purge.c). */
    ngx_atomic_t             tag_cap_drops;

    /* P4-1a: W-TinyLFU frequency sketch (count-min, 4-bit counters).
     *
     * STAGE 1 OF 2. This stage only ESTIMATES frequency; nothing reads the
     * estimate to make a decision, so admission and eviction behaviour is
     * byte-for-byte what it was before. Stage 2 adds the admission test at
     * store_locked() against the probation-tail victim.
     *
     * Layout: `sketch` is a flat array of `sketch_width * SKETCH_ROWS / 2`
     * bytes -- two 4-bit counters packed per byte, low nibble first. Row `r`
     * owns the counter range [r * sketch_width, (r+1) * sketch_width). An
     * estimate is the MIN across the four rows, which is what makes a
     * count-min sketch's error one-sided (it can over-count on collision,
     * never under-count).
     *
     * ⚠ `sketch` may be NULL and that is a SUPPORTED state, not an error.
     * The slab allocation in _shm_init_zone() is best-effort: a zone too
     * small to spare the sketch, or an allocation that loses a race with
     * entries, degrades to "estimate unavailable" (sketch_estimate() returns
     * 0) rather than failing zone init and taking the whole cache down for a
     * frequency hint. Every reader must tolerate NULL.
     *
     * ⚠ RELOAD / INHERITED ZONE. _shm_init_zone() returns early when it
     * inherits a live `sh` (octx, or shm.exists) -- these fields come with it
     * and are already valid, which is the desired behaviour: frequency
     * history survives a config reload. A zone created by an OLDER binary
     * that predates these fields and then inherited through `shm.exists`
     * would hand us bytes that were never initialised. That case is covered
     * by nginx's own shm handling rather than by a magic here: `shm.exists`
     * is only true for an inherited mapping within one master's lifetime
     * (a binary upgrade re-execs the master, which re-creates the zones from
     * the new binary), and a zone whose size or name changed is re-created
     * outright. Adding a version word would not make the mixed-binary case
     * safe either, since the OLD binary would still be writing entries into
     * a struct with a different layout -- that hazard predates this field and
     * is not one a guard here can close. Concluded: no magic/version guard.
     *
     * SIZE. sketch_width counters/row * 4 rows / 2 counters-per-byte. The
     * width is derived from the zone size in _shm_init_zone() and capped so
     * the sketch is well under 1% of the zone; see the sizing comment there.
     *
     * `sketch_ops` counts bumps since the last halving; when it reaches
     * `sketch_reset_at` every counter is halved (>>= 1) and it returns to 0.
     * That is the classic TinyLFU aging step: it keeps the estimates a
     * measure of RECENT frequency rather than of lifetime totals, so a key
     * that was hot last week cannot outrank one that is hot now.
     * `sketch_gen` counts how many halvings have happened, purely for
     * diagnosis. All three are plain fields, not atomics: every access is
     * under the shpool mutex. */
    u_char                  *sketch;
    ngx_uint_t               sketch_width;      /* counters per row          */
    ngx_uint_t               sketch_ops;        /* bumps since last halving  */
    ngx_uint_t               sketch_reset_at;   /* halve when ops reaches it */
    ngx_uint_t               sketch_gen;        /* halvings so far           */

    /* P4-1b: W-TinyLFU ADMISSION. `admission` mirrors the zone's
     * `cache_turbo_zone ... admission=on` parameter into shared memory so
     * ngx_http_cache_turbo_shm_store_locked(), which only ever receives the
     * zone (its L1-vtable signature carries no loc conf), can read the policy
     * without a signature change. Zero == OFF, which is the shipped default,
     * so an inherited or zeroed zone is inert.
     *
     * `sketch_bumps` is the lifetime bump tally (sketch_ops resets on every
     * halving, so it cannot answer "is the sketch learning anything at all?").
     * `admission_refused` counts candidates this policy turned away.
     * Both are plain fields, like every other sketch field: every access is
     * under the shpool mutex. */
    ngx_uint_t               admission;         /* 0 = off (default)         */
    ngx_uint_t               sketch_bumps;      /* lifetime bumps            */
    ngx_uint_t               admission_refused; /* candidates refused        */

    /* P4-2-s3a: LIVE gauge of slab bytes currently charged for cached
     * payload+metadata -- every node allocation plus every response blob
     * (blobref header included). Charged in shm_alloc_evict(), the sole
     * allocation funnel, and discharged in shm_free_locked(), the sole free
     * funnel, both under this same shpool mutex, so a charge without a matching
     * discharge is a structural impossibility rather than a per-site promise.
     * Excludes fixed per-zone init overhead (the shctx itself, the W-TinyLFU
     * sketch), which is never freed and would otherwise be an unreachable
     * floor. Against ngx_slab's own free-page accounting this is the DEMAND
     * side: the delta between the two is slab fragmentation + bin rounding,
     * which is precisely what P4-2-s3 needs a number for. Plain field, not an
     * atomic: every access is under the shpool mutex. */
    ngx_uint_t               used_bytes;
#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    /* O4.4-i: lifetime count of breaker-fallback ARMINGS, bumped inside the
     * breaker_should_consult() branch at each of the two arming sites (L1
     * expired-entry, L2 fallback). Exists solely to give those two sites a
     * negative control: the black-box runtime test cannot isolate them, because
     * the pre-origin gate alone already blocks BRK_ACT_SERVE when the breaker
     * is off, so a site reverted to a bare `threshold > 0` check keeps the
     * end-to-end test green (verified in s138 by injecting exactly that).
     *
     * ⚠ The bump MUST stay INSIDE the should_consult() branch. Bumped outside
     * it, this counts arming ATTEMPTS and goes vacuous in the same way the
     * black-box test did.
     *
     * TEST_FAULTS-gated rather than a plain counter so no permanent public
     * admin-JSON field exists only to serve a test. Production and package
     * builds do not define the macro and so have neither the field nor the
     * header that reports it.
     *
     * ⚠ PER SITE, not one shared counter. A single counter bumped at both
     * arming sites cannot pin either of them: on a fixture that arms from L2,
     * the L1 site runs first, the shared counter moves, and the assertion
     * credits L2 for L1's bump -- so an L2 mutation stays green. That was
     * measured, not theorised (a session applied the L2 mutation, rebuilt, and
     * the test still PASSED), which is why the split exists. Each site bumps
     * only its own field, so a delta on _l2 can only have come from the L2
     * site. */
    ngx_atomic_t             test_brk_armings_l1;
    ngx_atomic_t             test_brk_armings_l2;

    /* H-2/O4.4-j: lifetime count of times the reclaim predicate's `else`
     * (ngx_http_cache_turbo_shm.c, ngx_http_cache_turbo_shm_breaker_state())
     * was reached with an observed generation MISMATCH (open_for > 0 &&
     * probe.gen != NO_PROBE && probe.gen != state.gen) -- i.e. a wedge
     * candidate, the H-2 condition. Part 1 closes the only known
     * reachable producer (the masked-generation ABA wrap) at compile time,
     * so this should read 0 in any real deployment; it exists to make a
     * wedge OPERATOR-VISIBLE rather than silent if that analysis is ever
     * wrong, or a future change reopens a producer.
     *
     * TEST_FAULTS-gated for the same reason test_brk_armings is (O4.4-i):
     * a prior session rejected adding a permanent public admin-JSON field
     * purely to serve a test. This is diagnostic, not test-only, but the
     * module currently has no other precedent for a permanent counter that
     * is not otherwise operationally load-bearing (breaker_opens feeds the
     * admin JSON because operators act on trip counts directly) -- so it
     * follows the existing TEST_FAULTS convention rather than adding a new
     * one unilaterally. See the O4.4-h/H-2 decision packet in the grind
     * ledger for the "permanent public field" vs "TEST_FAULTS-gated" choice
     * this mirrors. */
    ngx_atomic_t             breaker_wedge_observed;
#endif
} ngx_http_cache_turbo_shctx_t;


/*
 * P4-2-s3b: the STRIPE SEAM.
 *
 * Historically a zone held exactly ONE (sh, shpool) pair, and every one of the
 * 64 code sites in the module dereferenced `z->shpool` / `z->sh` directly.
 * That single pair is the chokepoint that makes the zone mutex zone-wide: one
 * `ngx_slab_pool_t`, therefore one `ngx_shmtx`, therefore every key in the zone
 * serializes against every other key.
 *
 * This struct turns that pair into an ARRAY ELEMENT, and the resolvers below
 * turn every dereference into a lookup. Nothing about the runtime changes yet:
 * `nstripes` is hard-wired to 1 (NGX_HTTP_CACHE_TURBO_STRIPES == 1), so
 * `ngx_http_cache_turbo_stripe_of()` provably returns `&z->stripes[0]` for
 * EVERY input, and `ngx_http_cache_turbo_zone_stripe()` is that same element.
 * The seam is behaviour-identical by construction: one pool, one mutex, one
 * `used_bytes` gauge, exactly as before.
 *
 * s3c makes N configurable and carves N real pools. Only then does the
 * resolver start returning something other than element 0 -- and by then every
 * call site already asks it, rather than assuming.
 *
 * ⚠ INVARIANT: NO code outside the two resolvers below may name `->shpool` or
 * `->sh` on a zone. `ci/tools/lint-stripe-seam.sh` enforces this; a bare
 * `z->shpool` reintroduces the ability to lock pool A while freeing into pool
 * B, which is heap corruption under the wrong mutex.
 */
typedef struct {
    ngx_http_cache_turbo_shctx_t  *sh;
    ngx_slab_pool_t               *shpool;
} ngx_http_cache_turbo_stripe_t;


/* Compile-time stripe count. s3b pins this at 1; s3c turns it into a
 * per-zone runtime value with 1 as the default. Anything that depends on the
 * count reads z->nstripes, never this macro, so s3c is a value change and not
 * another site sweep. */
#define NGX_HTTP_CACHE_TURBO_STRIPES  1


typedef struct {
    /* P4-2-s3b: the stripe array. Exactly NGX_HTTP_CACHE_TURBO_STRIPES (== 1)
     * elements today. Reach it ONLY through ngx_http_cache_turbo_stripe_of()
     * or ngx_http_cache_turbo_zone_stripe(). */
    ngx_http_cache_turbo_stripe_t  stripes[NGX_HTTP_CACHE_TURBO_STRIPES];

    /* Live stripe count. Set to NGX_HTTP_CACHE_TURBO_STRIPES at zone init and
     * never changed while N == 1. Held as a field rather than read from the
     * macro so s3c only has to change where it is ASSIGNED. */
    ngx_uint_t                     nstripes;

    /* O4.4-d: config-time-only "first policy seen" accumulator for the
     * breaker tuple this zone is bound to. NOT shm state -- this struct is
     * allocated from cf->pool (see cache_turbo_zone's handler), so these
     * fields cost zero shared memory and never cross a worker boundary.
     * Populated the first time a location with a live breaker (per
     * ngx_http_cache_turbo_breaker_should_consult()) merges against this
     * zone; every later location on the same zone is compared against it.
     * policy_seen guards the "first" case; the recorded tuple is the
     * EFFECTIVE post-merge values, matching what _breaker_state() actually
     * receives (deliberately not a *_raw explicitness sidecar -- see
     * O4.4-d ledger). */
    ngx_flag_t               policy_seen;
    ngx_uint_t               policy_threshold;
    time_t                   policy_window;
    time_t                   policy_open;
    time_t                   policy_retry_after;

    /* P4-1b: the zone's parsed `admission=on|off` parameter. Config-time,
     * cf->pool-resident, copied into shctx_t.admission by init_zone(). 0 =
     * off, the shipped default. */
    ngx_uint_t               admission;
} ngx_http_cache_turbo_zone_t;


/*
 * P4-2-s3b: THE STRIPE RESOLVERS. The only two places in the module allowed to
 * name `->stripes`, and therefore the only places that can produce a
 * `ngx_slab_pool_t *` or a `ngx_http_cache_turbo_shctx_t *`.
 *
 * ngx_http_cache_turbo_stripe_of() is the KEY-directed resolver: it answers
 * "which stripe owns this key". While z->nstripes == 1 the modulo is a
 * provable identity -- `anything % 1 == 0` for every unsigned input, including
 * 0 and NGX_MAX_UINT32_VALUE -- so it returns &z->stripes[0] unconditionally
 * and the seam is behaviour-identical. The `nstripes <= 1` short-circuit is not
 * an optimisation dodging that proof; it is the fail-safe for a zone whose
 * init has not run (nstripes == 0), where the modulo would be a division by
 * zero.
 *
 * ngx_http_cache_turbo_zone_stripe() is the ZONE-WIDE resolver, for state that
 * is not per-key: init/teardown, the zone-global counters, the autotune
 * recompute, the breaker. Under N == 1 it is the same element the key resolver
 * returns; under s3c's N > 1 each of its call sites becomes a decision (fan out
 * over all stripes, or pin stripe 0), which is exactly the review that s3c
 * owes and s3b deliberately does not preempt.
 *
 * Both are inline and const-free on purpose: they must compile to the same
 * load a bare `z->shpool` did, so this port costs nothing at N == 1.
 */
static ngx_inline ngx_http_cache_turbo_stripe_t *
ngx_http_cache_turbo_stripe_of(ngx_http_cache_turbo_zone_t *z, uint32_t key)
{
    if (z->nstripes <= 1) {
        return &z->stripes[0];
    }

    return &z->stripes[key % (uint32_t) z->nstripes];
}


static ngx_inline ngx_http_cache_turbo_stripe_t *
ngx_http_cache_turbo_zone_stripe(ngx_http_cache_turbo_zone_t *z)
{
    return &z->stripes[0];
}


/* Sugar over ngx_http_cache_turbo_zone_stripe(). Every former `z->shpool` /
 * `z->sh` site reads as one of these, so the diff is a rename at the call site
 * and the seam is still the only path to a pool. */
#define ngx_http_cache_turbo_zone_pool(z)  (ngx_http_cache_turbo_zone_stripe(z)->shpool)
#define ngx_http_cache_turbo_zone_sh(z)    (ngx_http_cache_turbo_zone_stripe(z)->sh)

/* Zone-wide mutex, i.e. the mutex of the stripe that owns zone-global state.
 * Kept as a distinct spelling from zone_pool()->mutex so s3c can find every
 * lock site without re-deriving it from the pool expression. */
#define ngx_http_cache_turbo_zone_mutex(z) (&ngx_http_cache_turbo_zone_pool(z)->mutex)


/* Snapshot of the L1 zone's atomic counters. Filled by the l1 backend's stats
 * op and rendered by the admin GET handler, so the JSON formatting never touches
 * the live shctx directly. */
typedef struct {
    ngx_atomic_uint_t   hits;
    ngx_atomic_uint_t   misses;
    ngx_atomic_uint_t   stale_serves;
    ngx_atomic_uint_t   refreshes;
    ngx_atomic_uint_t   evictions;
    ngx_atomic_uint_t   l2_hits;
    ngx_atomic_uint_t   l2_misses;
    ngx_atomic_uint_t   lock_waits;   /* v10 coalesced cold-misses (waited)   */
    ngx_atomic_uint_t   min_uses_skips; /* v15 cold misses below min_uses     */
    ngx_atomic_uint_t   l2_neg_skips;   /* L13 L2 GETs skipped by a memo      */
    ngx_atomic_uint_t   bypasses;     /* bypass / auto-classify skips to origin */
    /* P4-1b: W-TinyLFU admission introspection. sketch_gen = halvings so far
     * (0 means the sketch has never aged, i.e. either brand new or absent);
     * sketch_bumps = lifetime bumps (0 with a live zone means the sketch was
     * never allocated); admission_refused = candidates the policy turned
     * away. Together they let an operator tell "admission is off" from
     * "admission is on and refusing nothing". */
    ngx_atomic_uint_t   sketch_gen;
    ngx_atomic_uint_t   sketch_bumps;
    ngx_atomic_uint_t   admission_refused;
    /* P4-2-s3a: live used-bytes gauge, see the shctx_t field. */
    ngx_atomic_uint_t   used_bytes;
    /* C3: live L1 auto-Vary marker presence gauge, see the shctx_t field. */
    ngx_atomic_uint_t   markers;
    /* P0-1: per-reason store-refusal counters, mirrors shctx_t. */
    ngx_atomic_uint_t   refuse_set_cookie;
    ngx_atomic_uint_t   refuse_encoded;
    ngx_atomic_uint_t   refuse_vary_unsafe;
    ngx_atomic_uint_t   refuse_authorization;
    ngx_atomic_uint_t   refuse_cache_control;
    ngx_atomic_uint_t   refuse_require_header;
    ngx_atomic_uint_t   refuse_partial;
    ngx_atomic_uint_t   refuse_head;
    /* Autotune introspection (v4-3): cost_ms = the measured average origin-regen
     * cost (cost_sum_ms / cost_count, 0 when nothing measured); autotuned_beta =
     * the live verdict ×1000 (0 = none). Rendered by the admin GET so a test (or
     * an operator) can see the live tuning without an internal probe. */
    ngx_atomic_uint_t   cost_ms;
    ngx_atomic_uint_t   autotuned_beta;
    ngx_atomic_uint_t   autotuned_load;   /* v4-4 load factor ×1000 (1000 = none) */
    /* P6/O4.1 breaker introspection: the raw state id (rendered as a string by
     * _breaker_state_str) and the lifetime CLOSED→OPEN trip count. Snapshotted
     * raw -- the stats op must never call _breaker_state(), which transitions. */
    ngx_atomic_uint_t   breaker_state;
    ngx_atomic_uint_t   breaker_opens;
    /* S7.1: production serve/failure counters. See the shctx field block for
     * exact semantics of each. */
    ngx_atomic_uint_t   sie_serves;
    ngx_atomic_uint_t   breaker_serves;
    ngx_atomic_uint_t   origin_failures;
    /* COR-5(b)/L9: store-time index writes dropped before reaching the
     * transport (S231 backoff armed, connect failure, alloc failure).
     * varidx_drops is the auto-Vary variant index (self-heals on the next
     * hit -- see varidx_reissues in shctx_t); tag_index_drops is the
     * purge-by-tag index, which has no self-heal. Neither counter changes
     * production behaviour; both exist so a dropped write is OBSERVABLE
     * instead of silent. */
    ngx_atomic_uint_t   varidx_drops;
    ngx_atomic_uint_t   tag_index_drops;
    /* TAG-CAP-SILENT-DROP: tags truncated by the MAX_TAGS cap before they
     * could ever be indexed -- see the shctx field comment above for how
     * this differs from tag_index_drops. */
    ngx_atomic_uint_t   tag_cap_drops;
    /* P3-7: live count of background-refresh subrequests in flight right
     * now (a gauge, not a counter -- goes up on fire, down on completion).
     * Answers exactly the "invisible to the module's own metrics" gap the
     * cap was added to close: an operator can see the cross-key total
     * saturating cache_turbo_background_update_max, which no per-key
     * metric could ever show. */
    ngx_atomic_uint_t   bg_inflight;
} ngx_http_cache_turbo_stats_t;


/*
 * Backend vtables (v4-1, #6). Two tiers, two interfaces: the local L1 store
 * (synchronous, in-process shm) and the remote L2 driver (asynchronous, parks
 * the request). They are deliberately NOT fused behind one get() — the SWR dice
 * / serve-stale branching lives between the L1 lookup and the L2 consult in the
 * access handler (see history.md v4-1). Forward-declared here so loc_conf can
 * hold pointers; the full definitions are at the foot of this header (after the
 * request ctx + members callback typedef they reference).
 */
typedef struct ngx_cache_turbo_l1_backend_s  ngx_cache_turbo_l1_backend_t;
typedef struct ngx_cache_turbo_backend_s     ngx_cache_turbo_backend_t;


/* One per-status fresh-TTL rule (v6): "cache this status for this long". */
typedef struct {
    ngx_uint_t   status;     /* HTTP status code (e.g. 301, 404)  */
    time_t       valid;      /* fresh TTL in seconds (0 = forever) */
} ngx_http_cache_turbo_valid_t;


/* location-level configuration */
typedef struct {
    ngx_flag_t               enable;
    ngx_shm_zone_t          *shm_zone;
    ngx_http_complex_value_t *key;        /* cache key expression           */

    /*
     * Preset + the knobs it controls (v3-2). The *_raw fields hold the explicit
     * directive value (or NGX_CONF_UNSET); they are what the directive slots
     * write and what merge inherits down the tree WITHOUT a literal default, so
     * a knob stays UNSET until a real directive sets it at some level. The
     * non-raw fields (valid/beta/lock_ttl/stale_mult/min_uses) are the EFFECTIVE
     * values (every one of the five now has a directive and therefore a *_raw
     * twin) the request path reads: in merge_loc_conf each resolves to its *_raw
     * value if set, else the resolved preset's band value. Keeping raw separate
     * from effective is what lets a location's preset still win when an ancestor
     * only resolved the effective default — see the note in merge_loc_conf.
     */
    ngx_int_t                preset;      /* one of PRESET_* or UNSET       */
    time_t                   valid_raw;   /* explicit cache_turbo_valid      */
    ngx_int_t                beta_raw;    /* explicit cache_turbo_beta       */
    time_t                   lock_ttl_raw;/* explicit cache_turbo_lock_ttl   */
    ngx_int_t                stale_mult_raw;
                                          /* explicit cache_turbo_stale_mult */
    ngx_int_t                min_uses_raw;
                                          /* explicit cache_turbo_min_uses   */

    /* S8 scan-resistant segmented LRU. `cache_turbo_scan_resistant off` (the
     * default) stores 0 here, which every LRU path reads as "flat LRU, behave
     * exactly as before S8". `on` stores the protected-segment cap as a
     * percentage (1..99, default 80). One field carries both the on/off state
     * and the tuning, so there is no way to be "on with pct 0". */
    ngx_uint_t               scan_resistant_pct;

    time_t                   valid;       /* fresh TTL (seconds), effective */
    ngx_int_t                beta;        /* SWR aggressiveness /1000, eff  */
    time_t                   lock_ttl;    /* single-flight lock window, eff */
    ngx_int_t                stale_mult;  /* stale window multiplier, eff   */

    /* Per-status TTLs (v6). cache_turbo_valid with leading status codes, e.g.
     * `cache_turbo_valid 301 302 1h; cache_turbo_valid 404 410 1m;`. Lets the
     * cache store redirects and negative responses, each with its own fresh TTL.
     * Array of ngx_http_cache_turbo_valid_t; NULL = only 200 is cacheable (at
     * clcf->valid). 200's TTL stays the bare `cache_turbo_valid TIME` value. */
    ngx_array_t             *valid_status;

    /* Bypass / no-store predicates (v9), like proxy_cache_bypass / proxy_no_cache.
     * Each is an array of complex values; a request "trips" the predicate when any
     * evaluates to a non-empty string other than "0". bypass => don't serve from
     * cache (still store the fresh response); no_store => don't store. Both NULL
     * by default. */
    ngx_array_t             *bypass;
    ngx_array_t             *no_store;

    /* Manual DIY equivalents of the preset URI-bypass and key-cookie engines
     * (v15), for an app we ship no preset for.
     *
     * bypass_uri: array of ngx_str_t URI prefixes. A request whose r->uri
     * matches any prefix on a path-segment boundary ('/' or '.') skips the
     * cache entirely — the same origin-and-never-capture semantics as a preset
     * URI rule (ngx_http_cache_turbo_auto_skip), evaluated by the SAME
     * ngx_http_cache_turbo_uri_prefix() matcher, but WITHOUT needing a preset.
     * This is what nginx `location` prefixes cannot express: they anchor at
     * position 0 and have no segment-boundary semantics, so mounting the app in
     * a subdirectory silently mis-matches.
     *
     * key_cookies: array of ngx_str_t cookie names whose VALUE is folded into
     * the cache key (tier-3 value-keying) via the same unforgeable
     * length-prefixed framing the presets use in build_key. EXACT name match,
     * ALL Cookie headers scanned. KEY, never bypass, never presence — see the
     * key_cookies field on ngx_http_cache_turbo_preset_t and the fold in
     * ngx_http_cache_turbo_build_key for the full rationale (a value-key is for
     * a SEGMENT FINGERPRINT the app shares across many visitors, not an
     * identity; presence-keying leaks). Both NGX_CONF_UNSET_PTR until set. */
    ngx_array_t             *bypass_uri;
    ngx_array_t             *key_cookies;

    /*
     * P5-8 (cache_turbo_ignore_set_cookie): array of ngx_str_t cookie NAMES the
     * operator declares ignorable, the module's equivalent of nginx
     * `proxy_ignore_headers Set-Cookie` -- except NAMED, not blanket. A response
     * whose EVERY Set-Cookie names a cookie on this list may be stored despite
     * the Set-Cookie floor; one unlisted name, one value this module cannot
     * parse unambiguously, or ANY key cookie being configured (preset or DIY)
     * refuses the store exactly as before.
     *
     * The stored blob never carries the cookie: Set-Cookie is on the
     * unconditional header_skip[] list, so it is dropped at serialisation and
     * cannot replay to a different client. The relax changes WHETHER the body is
     * stored, never WHAT is stored.
     *
     * NGX_CONF_UNSET_PTR until set; absent the directive the floor is
     * byte-identical to before. */
    ngx_array_t             *ignore_set_cookie;

    /*
     * S232-BYPASS-STALE (cache_turbo_bypass_stale_uri): array of ngx_str_t URI
     * prefixes whose responses are stored ONLY as circuit-breaker fallback --
     * matched by the same segment-boundary ngx_http_cache_turbo_uri_prefix()
     * as bypass_uri, for the same subdirectory-install reason.
     *
     * The problem this solves: a bypassed URL skips the lookup AND vetoes
     * capture, so when the origin dies the breaker has nothing to serve and the
     * client gets a 503. That is the correct PRIVACY default and is NOT relaxed
     * here.
     *
     * ⚠ Deliberately INDEPENDENT of bypass / bypass_uri rather than a flag on
     * them. An operator's bypass rules mean "never cache this", and they cover
     * per-user surfaces (cart, checkout, my-account). A knob that reinterpreted
     * those existing rules as cacheable-during-an-outage would silently turn
     * every one of them into a cross-user disclosure, precisely during an
     * incident when nobody is reading logs. So eligibility is never inherited:
     * the operator names the URIs here, explicitly, and a cookie-bypassed
     * request never becomes eligible by matching some other rule.
     *
     * The stored entry carries BLOBF_BREAKER_ONLY, so it is unreachable on the
     * normal hit path at ANY age -- only the pre-origin breaker gate can serve
     * it, and only while the breaker is OPEN. Point these at surfaces that are
     * shared by construction (a public catalog/inventory API), never at an
     * authenticated per-user response: the breaker serves ONE stored body to
     * every client, so a per-user body here IS a cross-user leak.
     *
     * NGX_CONF_UNSET_PTR until set. */
    ngx_array_t             *bypass_stale_uri;

    /* cache_turbo_backend_prefix: mount point of a subdirectory install, e.g.
     * "/shop/" for a WordPress served from https://example.com/shop/. Preset
     * uris[] rules are literals anchored at byte 0 ("/wp-admin/"), so without
     * this a subdirectory install matches NO URI rule at all and its admin
     * surface is cacheable. When set and r->uri starts with it, the preset URI
     * tier compares against the URI with this prefix removed.
     *
     * Scope is deliberately narrow — the PRESET uris[] tier only
     * (ngx_http_cache_turbo_auto_skip). NOT bypass_uri: those prefixes are
     * user-authored literals already written against the deployed path, so
     * stripping would break a rule the operator spelled out in full. NOT the
     * cookie or arg tiers: both are path-independent.
     *
     * Unrelated to the L2 "prefix=" param on cache_turbo_redis /
     * cache_turbo_memcached, which namespaces CACHE KEYS, not URI paths.
     *
     * Must begin and end with '/'. NGX_CONF_UNSET_PTR until set. */
    ngx_str_t               *backend_prefix;

    /* Auto-classify (cache_turbo <zone> auto / cache_turbo_backend <name>...).
     * A bitmask of CMS cacheability presets; 0 = manual mode (off). Each set
     * bit applies a curated set of "this request is dynamic, never cache it"
     * heuristics (login/session cookie prefixes, backend URI prefixes, dynamic
     * query args) evaluated in the access handler. `auto` and `backend generic`
     * set the union of all presets; naming specific backends composes only
     * those. Sits UNDER manual bypass/no_store overrides. See the preset
     * registry and ngx_http_cache_turbo_auto_skip() in the .c. */
    ngx_uint_t               backend_presets;
    ngx_uint_t               backend_key_cookies;

    /* Live autotune (v4-3). When on, the request path uses the zone's live
     * autotuned beta (clamped to this location's preset band) in place of the
     * static effective beta above; the per-zone recompute is throttled to a
     * fixed NGX_HTTP_CACHE_TURBO_AT_INTERVAL (30s) cadence. Off by default —
     * beta then resolves purely from preset as before. The clamp band is
     * ngx_http_cache_turbo_bands[preset]. */
    ngx_flag_t               autotune;       /* cache_turbo_autotune on|off    */

    /* Response Cache-Control handling, set by `cache_turbo_cache_control
     * respect|honor|ignore`. cc_mode is the raw tri-state (UNSET until set, so
     * a CMS preset can default it to "honor"); honor_cc/ignore_cc are derived
     * from it at merge and are what the request path reads — the runtime logic
     * is unchanged from when these were two separate directives.
     *
     *   respect (default): the response Cache-Control gates storage + reshapes
     *     the stale window as written; the fresh TTL comes from cache_turbo_valid.
     *   honor: also take the fresh TTL from the response's own s-maxage / max-age
     *     (s-maxage wins) or Expires; fall back to cache_turbo_valid when absent.
     *   ignore: discard the response Cache-Control entirely (mirrors nginx
     *     `proxy_ignore_headers Cache-Control`) — no-store / no-cache / private /
     *     max-age=0 / s-maxage=0 no longer forbid storage, must-revalidate / swr /
     *     sie no longer reshape the window, and the TTL is cache_turbo_valid.
     *     The Set-Cookie and request-Authorization safety floors are NOT affected
     *     (a per-user response is still never cached). */
    ngx_uint_t               cc_mode;     /* CT_CC_* ; UNSET until configured */
    ngx_flag_t               honor_cc;    /* derived: cc_mode == CT_CC_HONOR  */
    ngx_flag_t               ignore_cc;   /* derived: cc_mode == CT_CC_IGNORE */
    size_t                   max_size;    /* max single response to cache   */

    /* Suppress native cache when stacked (Q1). When on, the $cache_turbo_active
     * variable reads "1" for a request cache-turbo is handling (enabled,
     * cacheable method, not bypassed/no_store), else "0". The operator wires
     * `proxy_no_cache $cache_turbo_active; proxy_cache_bypass $cache_turbo_active;`
     * so a stacked native proxy_cache/fastcgi_cache defers to us instead of
     * double-caching. Off by default => the variable is always "0", so the
     * wiring can stay in place permanently and be toggled by this one knob. */
    ngx_flag_t               suppress_native;
    ngx_flag_t               admin;       /* this location is an admin endpoint */
    ngx_shm_zone_t          *admin_zone;  /* zone the admin endpoint manages */

    /* PURGE method (v14). When on, a `PURGE <uri>` request to this caching
     * location drops that URI's entry from L1 (+ L2). Gate the location with
     * allow/deny. Off by default. */
    ngx_flag_t               purge;

    /* Background update / stale-while-revalidate (v8). When on (default), the
     * SWR dice-winner does NOT regenerate inline: it fires a background refresh
     * subrequest for its own URI and serves the stale copy immediately, so no
     * foreground request ever blocks on the origin. A failed bg refresh (origin
     * 5xx/timeout) never overwrites the entry, so the stale copy persists =
     * stale-if-error for free. Off restores the old block-and-serve-fresh
     * winner. Mirrors proxy_cache_background_update (but default on here). */
    ngx_flag_t               background_update;

    /* cache_turbo_background_update_max N (P3-7). Zone-wide cap on
     * CONCURRENT background-refresh subrequests (z->sh->bg_inflight), across
     * every key sharing the zone. warm_one() refuses to fire (falls back to
     * a plain stale serve, no regen) once the cap is reached. 0 = unlimited
     * (today's ungated behaviour, preserved as the default — see the
     * directive handler for why 0 was chosen over a nonzero default). Only
     * meaningful with background_update on; ignored otherwise. */
    ngx_int_t                background_update_max;

    /* cache_turbo_warm_max N (P5-2-p0). Ceiling on how many URLs a single
     * admin warm request (?url=... or ?url_file=...) may fire subrequests
     * for. Bounds one operator-triggered call's origin fan-out. Default 32
     * (NGX_HTTP_CACHE_TURBO_WARM_MAX_DEFAULT), matching the previous
     * hardcoded cap byte-for-byte unless an operator opts in; clamped at
     * config time to NGX_HTTP_CACHE_TURBO_WARM_MAX_CEILING. */
    ngx_int_t                warm_max;

    /* Cold-miss single-flight (v10). When on (default), the FIRST request to
     * cold-miss a key (no L1 node, L2 also misses) becomes the single
     * regenerator (per box via a stub shm node, cross-node via the v4-2 Redis
     * NX lock); concurrent first-hits for the same key WAIT (park + re-check)
     * up to lock_timeout for the winner to fill the cache, then serve it,
     * instead of all stampeding the origin. off restores the old behaviour
     * (every cold-miss goes straight to origin). Mirrors proxy_cache_lock /
     * proxy_cache_lock_timeout (but default on here). lock_ttl bounds the
     * winner's hold (self-heal). */
    ngx_flag_t               lock;          /* cache_turbo_lock on|off          */
    ngx_msec_t               lock_timeout;  /* max a loser waits, then origin   */

    /* Minimum uses before caching (v15), EFFECTIVE value — the explicit
     * directive lives in min_uses_raw above and this resolves to it if set, else
     * to the preset band's min_uses (H3c). cache_turbo_min_uses N stores a
     * response only after its key has cold-missed N times, so one-hit-wonder
     * URLs never occupy the cache. A per-key miss counter lives in a lightweight
     * L1 "counter node" (see ngx_http_cache_turbo_node_t.miss_count); the Nth
     * miss converts that node into the normal cold-miss winner that stores.
     * 1 = store on the first miss (feature off) and is the band value for every
     * preset except AGGRESSIVE, which uses 2 — so the default (BALANCED) is
     * unchanged from v15. Below the threshold a request goes to the origin but
     * is not captured, and a popular key already present in L2 is served from L2
     * regardless (the gate sits after the L2 consult). */
    ngx_int_t                min_uses;

    /* cache_turbo_min_uses_window N (P3-6). Seconds to retain the miss_count
     * on a counter node before resetting it. Without a window, miss_count
     * persists for the lifetime of the counter node (reset only on LRU
     * eviction), so two misses a week apart count the same as two a second
     * apart, admitting genuine one-hit-wonders that happen to recur. With a
     * window, a miss older than N seconds is discarded on the next access,
     * forcing recent misses to drive the min_uses decision. 0 = OFF (the
     * default, v15 behavior unchanged), meaning miss_count never resets until
     * the node is evicted. The window applies when the node is read for a miss
     * at the point miss_count is incremented, checking `now - last_access >
     * window` using the last_access value BEFORE the current access updates it.
     * Bounded by NGX_HTTP_CACHE_TURBO_MIN_USES_WINDOW_MAX (86400, 1 day). */
    time_t                   min_uses_window;

    /* cache_turbo_l2_negative_ttl N (L13). Seconds to remember that an L2 GET
     * missed a key, so the next cold request for it skips the L2 round-trip
     * instead of paying a full RTT to be told "absent" again. 0 = OFF (the
     * default in every preset -- not a band column, see the MIN/MAX comment).
     *
     * Bounded staleness by construction: nothing invalidates the memo when a
     * PEER node stores the key, so for up to N seconds this node may go to the
     * origin for an object L2 actually holds. That is a hit-rate cost, never a
     * correctness one -- the memo carries no body and can never cause a stale
     * serve. Keep N at a few seconds (the stampede it collapses is shorter than
     * that) and leave it off unless L2 misses dominate the miss path. */
    time_t                   l2_negative_ttl;

    /* cache_turbo_vary_marker_revalidate N (c-2). Seconds a warm L1 auto-Vary
     * marker may be trusted before a request revalidates it against the
     * authoritative L2 generation instead of serving the L1 answer
     * unconditionally. 0 = OFF (the default -- today's behaviour: an L1 hit
     * is authoritative forever, per vary_apply()'s existing contract).
     *
     * Closes a real gap: access_l1()/vary_apply() treats any warm, unexpired
     * L1 marker as authoritative and never consults L2, so a PURGE handled by
     * a PEER node bumps the generation there but this node's own warm L1
     * marker (node-local by design) keeps resolving the OLD generation until
     * it naturally expires -- unbounded under cache_turbo_keep_stale. This
     * directive node-local-window-bounds that gap by re-checking L2's gen no
     * more often than once per window per base key, reusing the EXISTING
     * access_l2_marker_get() GET (never a new per-request round trip -- see
     * that function's field comment on the negative-memo bypass this
     * directive needs). Gated on clcf->auto_vary: meaningless without the
     * marker machinery auto_vary provides. Requires auto_vary to be
     * meaningful (checked at the call site, not at config time -- unlike
     * key_encoded_origin this is a pure staleness-window tightening with no
     * correctness hazard if auto_vary is later turned off, so a config-time
     * refusal is not warranted; it simply becomes inert). */
    time_t                   vary_marker_revalidate;

    /* cache_turbo_keep_stale <off|time|forever> (S2.1; read side wired in
     * S2.2). Consulted on the store path, where it widens sie_window -- see
     * the `ttl > 0 && clcf->keep_stale > 0` and
     * `ttl > 0 && clcf->ignore_cc && clcf->keep_stale > 0` gates. 0 = OFF (the
     * default, today's behaviour unchanged); NGX_HTTP_CACHE_TURBO_FOREVER_TTL
     * for the `forever` keyword; otherwise the parsed+clamped seconds value.
     * Deliberately NOT a synonym for cache_turbo_valid's "0 = forever"
     * convention -- see the doc comment on the handler for why a bare 0 here
     * means off, not forever. */
    time_t                   keep_stale;

    /* cache_turbo_use_stale <off|error|timeout|http_NNN...> (S4.1). Bitmask,
     * see the NGX_HTTP_CACHE_TURBO_USE_STALE_* comment block for the full
     * contract. NGX_CONF_UNSET_UINT until merge; merges to
     * NGX_HTTP_CACHE_TURBO_USE_STALE_DEFAULT (today's "any 5xx" behaviour,
     * unchanged). Read on the request path by the stale-if-error gate in
     * ngx_http_cache_turbo_header_filter (S4.2). */
    ngx_uint_t               use_stale;

    /* cache_turbo_breaker on|off (O4.4). Separate on/off switch from the
     * module's own `enable`: a location can have cache_turbo on with the
     * breaker left off (today's behaviour, and the default), or the breaker
     * explicitly re-enabled/disabled per-location independently of caching
     * itself. NGX_CONF_UNSET until merge; merges to off (0) — see
     * ngx_http_cache_turbo_breaker_should_consult() for the full admission
     * rule this feeds. This is one of THREE independent ways to express
     * "breaker off": the flag itself, `breaker_threshold 0`, or
     * `breaker_window 0`. */
    ngx_flag_t               breaker_enable;

    /* P6/O4.2 circuit-breaker tuning. Fed to
     * ngx_http_cache_turbo_shm_breaker_record() from the request path; the
     * O4.3 serve-path read and the directives that set these are O4.4.
     *
     * ⚠ Both merge to 0, and 0 is INERT on purpose (see the contract in
     * _breaker_record(): threshold == 0 disables tripping, window == 0
     * likewise). O4.4 adds the parsers that can make either non-zero;
     * whether the breaker is actually consulted is decided by
     * ngx_http_cache_turbo_breaker_should_consult(), which additionally
     * requires breaker_enable and clcf->enable.
     *
     * NOT derived from `use_stale`. "Should I serve stale?" and "is the origin
     * down?" are different questions that merely overlap on 5xx: use_stale may
     * legitimately name 403/404/429, all of which are a HEALTHY origin
     * answering correctly. Counting those as origin failures would let a
     * 404-heavy site trip its own breaker and 503 everything while the origin
     * was fine. The breaker's failure test is 5xx-only -- see
     * ngx_http_cache_turbo_breaker_is_origin_failure(). */
    ngx_uint_t               breaker_threshold; /* failures to trip; 0 = off  */
    time_t                   breaker_window;    /* rolling window s; 0 = off  */

    /* P5-5r: cache_turbo_breaker_count_retries off|on. OPT-IN, default off,
     * unlike every other breaker knob above (which ship on/pre-tuned by
     * S231-DEFAULTS). proxy_next_upstream runs UNDERNEATH this module: by
     * the time the header filter records an outcome, nginx may already have
     * burned several peer attempts, each recorded as its own entry in
     * r->upstream_states with its own status/header_time, and folded the
     * final one into a single response this module sees. With this off
     * (the default), only that final attempt is recorded -- byte-for-byte
     * today's behaviour, so an existing deployment's trip point does not
     * move. With it on, every FAILED attempt that precedes the final one in
     * upstream_states also feeds the breaker as one additional failure via
     * the same ngx_http_cache_turbo_shm_breaker_record() call -- see
     * ngx_http_cache_turbo_breaker_retry_failures() in module.c, and the
     * ordering note on its call site in filters.c
     * (ngx_http_cache_turbo_header_filter_record_breaker()) for why this
     * only lets a SINGLE request's own retry chain trip the breaker, not a
     * trickle of failures smeared across separately-successful requests:
     * shm_breaker_record()'s success branch unconditionally clears the
     * failure run, so a later request's own success always erases an
     * earlier request's retry evidence. Left off by default because it
     * changes WHEN a request's own retries can trip the group: a site that
     * already free-rides on proxy_next_upstream retries today never trips
     * the breaker on those, no matter how many peers one request burns
     * through; turning this on makes such a request trip the breaker where
     * it previously could not, which is the point, but only for an
     * operator who asks for it. */
    ngx_flag_t               breaker_count_retries;

    /* P6/O4.3 serve-path tuning. Read by the pre-origin breaker gate in
     * ngx_http_cache_turbo_access_handler(); the directives that set them are
     * O4.4, so both still merge to their inert defaults here.
     *
     * breaker_open is the `open_for` argument of
     * ngx_http_cache_turbo_shm_breaker_state() -- how long an OPEN lasts before
     * ONE request is promoted to probe the origin. time_t (seconds), NOT msec:
     * that is the type the shm API takes.
     *
     * ⚠ 0 does NOT mean "no open window", it means NO TIMED REOPEN: the state
     * machine's guard is `open_for > 0`, so with 0 an OPEN breaker never
     * promotes a probe and stays open until a recorded success -- and while
     * OPEN nobody talks to the origin, so no success can ever be recorded. The
     * breaker would wedge permanently. It is inert today only because
     * threshold == 0 means it can never trip in the first place. O4.4's
     * `cache_turbo_breaker_open` directive REJECTS a literal 0 as a hard
     * config error rather than accept it as a disable — see
     * ngx_http_cache_turbo_breaker_open_conf(). Tracked as O4.3-a in memory
     * issues.md. Default merges to 30s (non-zero, unlike every sibling
     * breaker field). */
    time_t                   breaker_open;      /* OPEN duration s; never 0 */

    /* Retry-After seconds sent with the breaker's 503. Advisory to the client;
     * has no effect on the breaker's own timing.
     *
     * cache_turbo_breaker_retry_after is an explicit knob (NGX_CONF_UNSET
     * until set). When left unset, merge derives it from the EFFECTIVE
     * breaker_open rather than a hardcoded constant, so the two stay in sync
     * by default — the Retry-After hint then always names about when the
     * next probe is actually due. */
    time_t                   breaker_retry_after;

    /* L2 Redis (v2b). Native async client, no hiredis. The L2 store is touched
     * only on an L1 miss (sync GET) and on store (async write-through); it is
     * never on the L1-hit hot path. */
    ngx_flag_t               redis_enable; /* cache_turbo_redis configured     */
    ngx_addr_t               redis_addr;   /* resolved host:port               */
    ngx_str_t                redis_prefix; /* key prefix, default "ct:"        */
    ngx_msec_t               redis_timeout;/* connect/read timeout             */

    /* S231-L2-SCANTIME: wall-clock ceiling on one all-purge SCAN walk, checked
     * at every page boundary alongside SCAN_MAX_PAGES. The page cap alone is a
     * MEMORY guard: each page's read re-arms redis_timeout, so a server that
     * always returns a non-zero cursor just before that timer fires can park
     * the request for up to SCAN_MAX_PAGES pages (hours). scan_deadline= on
     * cache_turbo_redis sets it; 0 = disabled (unbounded, page-cap only). */
    ngx_msec_t               redis_scan_deadline;

    /* L2 per-worker connect backoff (S231). After a connect FAILURE (not a
     * protocol/reply error) to redis_addr, this worker fails L2 ops fast for
     * connect_backoff ms instead of paying a fresh connect() attempt on every
     * request during an L2 outage. Shared by both drivers (redis + memcached)
     * the same way redis_addr/redis_timeout already are: one L2 backend per
     * location, keyed by peer address, state kept in each driver's own
     * process-global table (mirrors the *_ka keepalive-pool pattern). 0 =
     * disabled (never back off); a nonzero value that is too small to matter
     * is still a config choice, not something this field validates. */
    ngx_msec_t               redis_connect_backoff;

    /* L2 memcached (v13). A second, simpler L2 backend selected by
     * cache_turbo_memcached HOST:PORT (mutually exclusive with cache_turbo_redis
     * — both reuse redis_addr/redis_prefix/redis_timeout/redis_enable; the flag
     * below picks the vtable). Text protocol, plain TCP, get/set/del/del_raw
     * only: tag/scan/lock vtable slots stay NULL (no SADD/SCAN/atomic-lock), so
     * tag-purge / purge?all / cross-node single-flight are unavailable on it.
     * 1 MB value cap (memcached's default item ceiling): oversized SET skipped. */
    ngx_flag_t               memcached;    /* cache_turbo_memcached configured  */

    /* Keepalive pool (v15; per-profile buckets v16). cache_turbo_redis
     * keepalive=N caches up to N idle L2 connections per worker, so an L2 op
     * reuses a live connection instead of connect()+close per op. 0 = off
     * (default). keepalive_timeout= closes an idle pooled connection after this
     * long. Each distinct connection profile (peer addr + db + credentials + TLS
     * context) gets its OWN bucket with its OWN N and timeout, taken from the
     * location that opens it — so per-location values are honoured and profiles
     * cannot starve each other (see ka_bucket() in the redis driver). TLS conns
     * are pooled too (v15-2): the persistent channel is reused, handshake +
     * preamble skipped on reuse. */
    ngx_int_t                redis_keepalive;        /* max idle conns, 0=off  */
    ngx_msec_t               redis_keepalive_timeout;/* idle close timeout     */

    /* Memcached keepalive pool (v14). cache_turbo_memcached keepalive=N caches
     * up to N idle L2 connections per worker. 0 = off (default). Memcached has
     * no auth/TLS/db, so identity = peer addr only (simpler than redis). */
    ngx_int_t                memcached_keepalive;        /* max idle conns, 0=off  */
    ngx_msec_t               memcached_keepalive_timeout;/* idle close timeout     */

    /* Full DSN (v5): cache_turbo_redis accepts redis://[user:pass@]host:port/db
     * (rediss:// = TLS), with prefix=/timeout=/password=/user=/db=/tls=/
     * tls_verify=/tls_ca=/tls_name= overrides. On each connection the driver
     * pipelines AUTH (+ optional ACL user) and SELECT <db> before the command;
     * rediss wraps the socket in TLS and (by default) verifies the server cert
     * against the system CA + the host name. */
    ngx_str_t                redis_user;    /* ACL username, "" = legacy AUTH   */
    ngx_str_t                redis_password;/* AUTH password, "" = no AUTH      */
    ngx_int_t                redis_db;      /* SELECT db index, 0 = no SELECT   */
    ngx_flag_t               redis_tls;     /* rediss:// or tls=on              */
    ngx_flag_t               redis_tls_verify; /* verify cert+host (default on) */
    ngx_str_t                redis_tls_ca;  /* CA bundle file, "" = system CAs  */
    ngx_str_t                redis_tls_name;/* verify/SNI name, "" = DSN host   */
    ngx_str_t                redis_host;    /* DSN host (default SNI/verify name)*/
#if (NGX_SSL)
    ngx_ssl_t               *redis_ssl;     /* per-location client SSL context  */
#endif

    /* Tag index (v2c). cache_turbo_tag evaluates to a whitespace/comma list of
     * tags; on store each tag set "<prefix>tag:<name>" gets the object's L2 key
     * SADD'ed (+EXPIRE), so a purge-by-tag can drop every keyed object across
     * both tiers. Tags live only in L2, so this needs cache_turbo_redis. */
    ngx_http_complex_value_t *tag;        /* tag list expression, or NULL     */

    /* cache_turbo_surrogate_key on|off. When on AND cache_turbo_tag is set, the
     * store path emits the parsed tag list back downstream as a Surrogate-Key
     * response header (RFC edge-arch / Fastly), so a CDN fronting this cache can
     * key the edge object on the same tags and stay purge-synced. Independent of
     * cache_turbo_redis: emitting the CDN header does not need a turbo L2 tag
     * index. MISS/store path only -- the CDN reads Surrogate-Key on the fetch
     * that populates its edge; subsequent hits are served from the edge. */
    ngx_flag_t               surrogate_key; /* cache_turbo_surrogate_key on|off */

    /* Explicit upstream store opt-in (cache_turbo_require_header <name>).
     * When set, a response is captured ONLY if it carries <name> with an
     * affirmative value ("yes"/"1"/"on", case-insensitive). Everything else --
     * header absent, "no", empty, unparseable -- refuses the store.
     *
     * This inverts the module's usual "cacheable unless something vetoes it"
     * default into "uncacheable unless the origin says otherwise", for origins
     * where only the application can decide: a GraphQL endpoint answers a query
     * and a mutation on the same URI+method, and returns errors as HTTP 200
     * with an `errors` member in the body. No amount of HTTP-level inspection
     * separates those, and the module deliberately does not parse the body
     * (it stays an opaque blob), so the decision has to come from upstream.
     *
     * Fails CLOSED by construction: any doubt = no store = a cache miss, never
     * a wrong serve. The name is stripped before store (like Age / the RFC 9213
     * targeted directives) -- this cache is its intended consumer, and a HIT
     * must not replay it downstream. len == 0 = unset (default). */
    ngx_str_t                require_header;

    /* Key normalize (v3-1). The $cache_turbo_normalized_args variable rebuilds
     * r->args dropping tracking params and sorting the rest, so requests that
     * differ only in arg order or carry junk (utm_*, fbclid, ...) hash to one
     * cache slot. Orthogonal to keying: the user composes the key from the
     * variable, e.g. cache_turbo_key $uri$cache_turbo_normalized_args. */
    ngx_array_t             *normalize_strip;     /* extra ngx_str_t patterns to
                                                   * deny, added to the built-in
                                                   * defaults; trailing '*' is a
                                                   * prefix match. NULL = none. */

    /* R3-3: first-byte bitmap over the combined denylist (built-in defaults +
     * normalize_strip), built once at config merge time so the per-request,
     * per-param fast path in ngx_http_cache_turbo_name_denied can reject a
     * non-matching first byte with one bit test instead of walking every
     * pattern. Two 128-bit (16-byte) halves so a byte and its opposite case
     * both hit -- matching is case-insensitive and names arrive unlowercased.
     * strip_bitmap_all is set when any pattern in the combined list is the
     * zero-length prefix "*" (cache_turbo_normalize_strip *), which must match
     * every name regardless of first byte -- the bitmap is not consulted then.
     * Built by ngx_http_cache_turbo_build_strip_bitmap(), called once from
     * merge_loc_conf after normalize_strip has its final (inherited or
     * overridden) value. */
    u_char                   strip_bitmap[32];
    unsigned                 strip_bitmap_all:1;

    /* Vary-aware suffix (v3-4). Bitmask of NGX_HTTP_CACHE_TURBO_VARY_* selecting
     * which buckets are appended to $cache_turbo_normalized_args so responses
     * that legitimately differ by encoding (br/gzip/identity) or device
     * (mobile/desktop) get separate cache slots. NGX_CONF_UNSET / 0 = off, so
     * v3-1 keys are unchanged unless cache_turbo_normalize_vary opts in. */
    ngx_int_t                normalize_vary;

    /* R3-1 DoS bound. $cache_turbo_normalized_args sorts the kept params with
     * an insertion sort (O(n^2)); `kept` is bounded only by r->args.len (~8k by
     * default), so an unauthenticated request with thousands of params burns
     * tens of ms of worker CPU BEFORE the cache lookup -- a hit cannot absorb
     * it. When the kept (post-strip) count exceeds this cap, normalization is
     * SKIPPED entirely and the RAW r->args string is used for the key: the
     * request is still served correctly and still keys consistently, it just is
     * not normalized. 0 = unlimited (no cap, pre-R3-1 behaviour).
     * NGX_CONF_UNSET merges to 64, the measured knee (~0.011 ms). */
    ngx_int_t                normalize_max_args;

    /* auto-Vary (v11 other half). When on, the response `Vary:` header is read
     * at store time and the named request headers (safe whitelist only:
     * Accept-Encoding, User-Agent->device, Accept-Language, Origin) are folded
     * into a SECONDARY variant key so distinct representations get distinct
     * slots automatically — no operator config of the axes. Two-level keying is
     * node-local: a tiny "vary marker" (the active axis bitmask) is stored in L1
     * under a dedicated marker key; a request probes the marker (L1 only) and,
     * if present, recomputes its key to the variant before the normal lookup.
     * The base slot stays empty for varied URLs, so a missing marker just misses
     * to origin (never serves the wrong variant). Vary: * / Cookie /
     * Authorization make the response uncacheable. Off by default. */
    ngx_flag_t               auto_vary;

    /* cache_turbo_key_encoded_origin (P3-2). An origin that always sends a
     * non-identity Content-Encoding (most Node/Python stacks with
     * compression middleware on) is otherwise 100% uncacheable, silently --
     * response_encoded() vetoes capture unconditionally. When ON, the
     * capture gate instead stores the origin's own pre-compressed bytes,
     * FORCES the VARY_ENCODING bit so the object is keyed by ae-class (the
     * same variant_hash/marker machinery auto_vary already uses), and stamps
     * BLOBF_ORIGIN_ENCODED + the packed ae-class on the blob so the serve
     * chokepoint (ngx_http_cache_turbo_serve() / _sie_rewrite()) refuses to
     * serve it to a client whose Accept-Encoding does not actually accept
     * that class. Requires auto_vary (the variant-keying machinery this
     * relies on) -- checked at merge time. Off by default: this only helps
     * an always-encoded origin, and does nothing for one that already
     * negotiates via Vary: Accept-Encoding (classify_vary() already handles
     * that case). */
    ngx_flag_t               key_encoded_origin;

    /* cache_turbo_serve_authorized (P3-4). The LOOKUP-side counterpart of the
     * Authorization floor. By default a request carrying Authorization is
     * declined in access_eligible() before any cache state is touched, so a
     * credentialed client can never READ an entry -- even the anonymously
     * stored, explicitly public copy of the very same URL. That costs every
     * hit on an API that authenticates each call to a shareable public
     * endpoint (hit ratio is exactly zero there today).
     *
     * When ON, an Authorization-bearing request is allowed to PROCEED to the
     * lookup and may be served an already-stored entry. The STORE floor in
     * ngx_http_cache_turbo_response_cacheable() is deliberately untouched:
     * its `r->headers_in.authorization != NULL` arm is the FIRST test in the
     * function, ungated by any directive, and ctx->captured (the sole gate on
     * the body filter's store, filters.c) is only set when it returns true.
     * So the set of entries this can expose is exactly the set stored by
     * requests that carried NO credentials -- relaxing the read side cannot
     * make a credentialed response reachable by anyone, because none is ever
     * written in the first place.
     *
     * RFC 9111 SS3.5 additionally requires an explicit shared-cache
     * authorisation to REUSE a stored response for an authenticated request,
     * so serving is further gated at the serve site on the stored response
     * carrying public / s-maxage / must-revalidate. Off by default: it widens
     * who may read a cached body, and an operator must assert that the
     * endpoint's public representation really is identical for every
     * principal. */
    ngx_flag_t               serve_authorized;

    /* cache_turbo_store_head on|off (P5-6, default off). When on, a HEAD
     * that misses the cache fires ONE internal background warm subrequest --
     * a real GET, header_only = 0, the same mechanism the SWR background
     * refresh uses -- so the URL gets an entry instead of being a permanent
     * 100%% miss. Monitors, link checkers and some crawlers issue HEAD and
     * nothing else, and such a URL is never populated otherwise (the capture
     * gate refuses HEAD outright, filters.c, because nginx core forces
     * r->header_only = 1 for HEAD once headers are sent and the body chain --
     * where every store in this module lives -- never runs).
     *
     * The resulting entry is stamped BLOBF_HEAD_DERIVED and the serve
     * chokepoint refuses it to any non-HEAD request; see that flag's comment
     * for the invariant and why it is enforced there. Default off because it
     * spends one extra origin body per HEAD-miss, which only pays for itself
     * on a workload that really is HEAD-dominated. */
    ngx_flag_t               store_head;

    /* cache_turbo_vary_ignore <header>... (P3-3). Header names (case-
     * insensitive match against tokens in a response Vary header) to drop
     * BEFORE classify_vary()'s whitelist/unsafe-axis check, i.e. treated as
     * if the origin never listed them at all -- NOT folded into the safe
     * whitelist and NOT contributing to the variant key. This is a
     * deliberate cache-correctness override: naming a header here means the
     * operator accepts that clients who would have received different
     * bodies for that axis now share one cached copy. Off by default
     * (NGX_CONF_UNSET_PTR = empty list, nothing ignored). Never widens the
     * built-in safe-axis whitelist (Accept-Encoding/User-Agent/
     * Accept-Language/Origin) -- an ignored axis is dropped, not promoted to
     * safe. "*", Cookie and Authorization are rejected at config time --
     * see ngx_http_cache_turbo_vary_ignore()'s own doc comment. */
    ngx_array_t             *vary_ignore;         /* ngx_str_t[], UNSET = none */

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    /* CI-only fault injection; production/package builds do not define the
     * feature macro and therefore expose neither this field nor its directive. */
    ngx_flag_t               test_restore_alloc_fail;
    /* Force the body filter onto the file-backed delegate path even when the
     * incoming buffers are in memory, so the sendfile-abort branch (which is
     * fs/directio-alignment dependent and non-deterministic in the harness) is
     * exercised deterministically. Delegates the UNMODIFIED in-memory chain
     * downstream and abandons capture; it does NOT forge b->in_file. */
    ngx_flag_t               test_force_file_buf;
    /* AUD-STORE-ERR-STUB: force the body filter's l1->store() call to fail
     * deterministically, so the cold-miss stub cleanup path (armed only when
     * store did NOT succeed) is reachable without depending on real slab
     * exhaustion timing. */
    ngx_flag_t               test_store_fail;
    /* COR-5(b): when on, a request carrying the header
     * X-Cache-Turbo-Test-Varidx-Drop: 1 has its auto-Vary variant-index write
     * SKIPPED at the store site, and the store site sees the same NGX_ERROR
     * redis_launch() returns inside an armed S231 connect-backoff window or
     * on a failed connect.
     *
     * ⚠ Driven by a REQUEST HEADER, not by a per-store countdown. The runtime
     * suite runs 4 workers with no request affinity, so a "drop the first N
     * stores" budget would live per-worker and the test could not say WHICH
     * variant lost its index entry. The header makes the fault a property of
     * the request, so it is deterministic whatever worker serves it.
     *
     * Real Redis stays UP on purpose: the test needs the object and the base
     * marker written normally and ONLY the index SADD lost, which is the
     * PR #379 signature. Taking the peer down would drop all three and the
     * purge would miss the variant for a different reason. */
    ngx_flag_t               test_varidx_fail;
    /* AUD-SCAN1: lower the SCAN-del page cap so the cap branch is reachable in
     * a test without materialising a 268M-key keyspace. 0 / unset keeps the
     * compile-time ceiling. Test-only for the same reason the cap itself is a
     * constant rather than a directive: the ceiling is a safety net, not a
     * tuning knob, and a public directive would invite operators to lower it
     * into routinely-incomplete purges. */
    ngx_int_t                test_scan_max_pages;
    /* AUD-L2-PROMOTE-RACE: milliseconds to block the CURRENT worker right
     * before the L2-promote store_if() call, so a test can race a concurrent
     * write from a different worker into the gap. 0/unset = no hold. See the
     * directive comment in the conf array for why this is a plain blocking
     * ngx_msleep rather than an async timer. */
    ngx_int_t                test_l2_promote_hold_ms;
    /* S231-L2-SCANTIME: milliseconds to block the worker at every SCAN page
     * boundary of an L2 all-purge, so the wall-clock deadline check is
     * REACHABLE deterministically. Without it the deadline test is a race
     * against runner speed: the walk's `cursor == 0` completion check returns
     * BEFORE the deadline check, so a keyspace small enough to finish inside
     * the page cap can answer 200 having never evaluated the deadline at all --
     * and ngx_current_msec is nginx's CACHED clock, refreshed at event-loop
     * wakeups, so a fast walk may observe no elapsed time whatsoever. Blocking
     * (ngx_msleep) for the same reason as test_l2_promote_hold_ms: the walk is
     * driven off one connection's read handler and an async timer would not
     * hold the page boundary. 0/unset = no hold. */
    ngx_int_t                test_scan_page_hold_ms;
    /* S231-SIE-MIDBODY: no production signal for "the upstream died after
     * sending headers but before last_buf" is reliable enough to trigger the
     * rescue from (see the body filter comment at the rescue site for the
     * candidates considered and rejected). This directive makes the body
     * filter treat the FIRST arriving buffer as that failure deterministically,
     * so the pre-flush rescue path is reachable in a test without depending on
     * upstream connection-teardown timing. */
    ngx_flag_t               test_midbody_abort;
    /* P3-7: force ngx_http_cache_turbo_warm_one()'s warm_anonymize() call to
     * fail deterministically (module.c), so a test can exercise the
     * "subrequest posted, ctx already seeded, then an early NGX_ERROR
     * return before the subrequest completes" hazard that makes the
     * bg_inflight decrement pool-cleanup-based rather than
     * return-value-based -- see the bg_inflight field comment in module.h.
     * Deliberately NOT the earlier ctx-alloc arm: forcing THAT
     * reintroduces the ctx-less "body forwarded, main->count never
     * dropped" hang s84 already fixed (see the ctx-alloc comment in
     * warm_one()), which would test a known-fixed bug instead of this
     * feature's own decrement. Without this hook the anonymize arm depends
     * on real pool exhaustion, which is not reproducible on demand. */
    ngx_flag_t               test_warm_ctx_fail;
#endif


    /* Backend vtables (v4-1). l1 = the local store (shm); it is a stateless
     * dispatch table (the zone is passed as an argument), so it is set
     * unconditionally and is never NULL. backend = the remote L2 driver (redis),
     * set when cache_turbo_redis is configured, else NULL — call sites guard on
     * it. Both are resolved in merge_loc_conf. */
    ngx_cache_turbo_l1_backend_t  *l1;
    ngx_cache_turbo_backend_t     *backend;
} ngx_http_cache_turbo_loc_conf_t;


/* per-request context */
typedef struct {
    unsigned                 ct_active:1; /* Q1: cache-turbo engaged for this
                                           * request (enabled, cacheable method,
                                           * not bypassed/no_store) -> the
                                           * $cache_turbo_active var reads 1     */
    unsigned                 auto_skip:1; /* auto-classify ruled this request
                                           * dynamic -> origin, never capture    */
    /* S232-BYPASS-STALE: r->uri matched cache_turbo_bypass_stale_uri. Bypasses
     * the LOOKUP like auto_skip (the stored copy must never answer a normal
     * request) but deliberately does NOT veto capture, so a breaker-only
     * fallback body exists. Sets BLOBF_BREAKER_ONLY on the stored blob. */
    unsigned                 brk_only:1;
    /* P3-2: this response is being captured as origin-pre-compressed under
     * cache_turbo_key_encoded_origin -- the body filter must stamp
     * BLOBF_ORIGIN_ENCODED + the packed ae-class on the stored blob. Set by
     * the capture gate, which also force-sets VARY_ENCODING into vary_bits
     * so the object stores under an ae-class variant key even though the
     * origin never sent a Vary: Accept-Encoding header for classify_vary()
     * to pick up. */
    unsigned                 origin_encoded_capture:1;
    /* P3-2: the packed NGX_HTTP_CACHE_TURBO_AE_CLASS_* value to stamp on the
     * blob when origin_encoded_capture is set -- only meaningful then. 2
     * bits is enough (0..3), matching BLOBF_AE_CLASS_MASK's width. */
    unsigned                 origin_encoded_class:2;
    /* P3-4: the response carried an RFC 9111 SS3.5 shared-cache reuse
     * authorisation (public / s-maxage / must-revalidate). Resolved in the
     * HEADER filter, where the response headers still exist, and consumed by
     * the body filter to stamp BLOBF_AUTH_SHAREABLE -- the body filter runs
     * after the headers have been sent and cannot re-derive it. Independent
     * of whether serve_authorized is on anywhere: the bit is recorded on
     * every stored blob so an operator can enable the directive later
     * without invalidating the cache. */
    /* P5-6: this response is being captured by a HEAD-triggered warm
     * subrequest (cache_turbo_store_head) -- the body filter must stamp
     * BLOBF_HEAD_DERIVED on the stored blob so the serve chokepoint can
     * refuse the entry to every non-HEAD request. Set on the SUBREQUEST's
     * ctx by warm_head_one(), never on a client request's ctx. */
    unsigned                 head_derived:1;
    /* P5-6: this request has already fired its cache_turbo_store_head warm
     * subrequest. The access handler re-runs from the top on every park/resume
     * (the L2 GET, the cross-node NX lock, each cold-wait re-poll), so without
     * this a single parked HEAD would fire one warm per re-entry. Set on the
     * CLIENT request's ctx, unlike head_derived which lives on the
     * subrequest's. */
    unsigned                 head_warm_fired:1;
    unsigned                 auth_shareable:1;
    unsigned                 captured:1;  /* response captured for store    */
    unsigned                 served:1;    /* we served from cache           */
    unsigned                 warm:1;      /* warm subrequest: force a miss,  */
                                          /* capture + store though !r->main */
    unsigned                 l2_done:1;   /* L2 GET finished (hit or miss)   */
    /* L2 GET outcome. TRI-STATE (L13-fix) -- callers that only care "did L2
     * satisfy this request" still test `== NGX_OK`, but anything that acts on a
     * MISS must distinguish the two failure kinds:
     *
     *   NGX_OK       L2 hit, blob in l2_blob
     *   NGX_DECLINED DEFINITIVE miss -- a well-formed reply said "not there".
     *                The only value that may arm the L13 negative memo.
     *   NGX_ERROR    TRANSPORT failure (timeout / closed conn / malformed reply /
     *                connect+send error / local alloc failure on an otherwise
     *                successful hit). L2's answer is UNKNOWN, not "absent".
     *
     * Mirrors the convention the cross-node lock path already uses (redis.c
     * lock_finish: NGX_ERROR on transport failure "so the caller degrades ...
     * rather than suppressing the refresh"). Same reasoning: an outage must never
     * suppress the operation that would notice recovery. */
    ngx_int_t                l2_result;
    u_char                  *l2_blob;     /* L2-hit blob, copied to r->pool  */
    size_t                   l2_blob_len;
    unsigned                 l2_miss_counted:1;/* l2_misses stat already bumped*/
    unsigned                 l2_neg_force:1;   /* L13: consult L2 for real on
                                                * this re-entry, ignoring any
                                                * memo -- set by the cold-miss
                                                * wait re-poll, whose whole
                                                * purpose is to catch a peer's
                                                * mid-wait write-through */
    unsigned                 l2_neg_skipped:1; /* L13: the L2 GET was skipped by
                                                * a negative memo rather than
                                                * actually performed -- keeps
                                                * the miss path from re-arming
                                                * the memo it just consumed */
    /* Cross-node dogpile (v4-2). On a stale L1 dice win the request parks for a
     * Redis SET NX PX reply: lock_result == NGX_OK means this node holds the
     * cluster-wide regen lock (go to origin); anything else means another node
     * owns it (serve stale, skip origin). Mirrors the l2_* park/resume trio.
     * lock_result == NGX_ERROR is a THIRD outcome (v16): the L2 lock channel
     * itself failed (timeout / connect error / EOF), distinct from a genuine
     * peer-holds-lock decline — the caller degrades to per-box single-flight
     * (regenerate locally) instead of suppressing the refresh, so a Redis
     * outage cannot freeze every node on serve-stale / cold-wait. */
    unsigned                 lock_done:1; /* NX reply landed                 */
    ngx_int_t                lock_result; /* NGX_OK=hold; NGX_ERROR=L2 down   */
    /* Cold-miss single-flight (v10). A cold-miss LOSER parks on a short timer
     * and re-checks L1/L2 until the winner fills the entry or lock_timeout
     * elapses. waiting marks this request as already in the wait loop (re-entry
     * must not re-claim); wait_deadline is the give-up time (ngx_current_msec
     * clock); cold_wait_ev is the per-request poll timer (data = r). */
    unsigned                 waiting:1;   /* in the cold-miss wait loop       */
    /* V-HANG-2: a cold-wait re-poll saw L2 HOLD this key but reject it as
     * unserveable (past its stored stale window). The fill we are waiting for
     * has therefore already happened and no further poll can change the answer
     * — keep waiting and we burn the rest of lock_timeout for nothing. Set on
     * the L2-hit-but-expired branch, checked at the top of the wait loop.
     *
     * ⚠ Only meaningful together with wait_polled below. The set site fires on
     * ANY L2-hit-but-expired lookup, including the very first one, so on its own
     * it cannot distinguish "the fill already landed" from "we have not waited
     * for the fill yet" — see wait_polled. */
    unsigned                 l2_present_unserveable:1;
    /* This request has completed at least one cold-wait POLL (it parked on the
     * timer and came back). Set at the park site, never cleared.
     *
     * The V-HANG-2 give-up above is only sound once this is set: it concludes
     * "the winner's fill has already landed" from seeing the key present in L2,
     * and that inference holds only for a re-poll. On the FIRST pass a
     * CLAIM_LOSER can see the same expired blob before the winner has written
     * anything — giving up there sends every loser straight to the origin and
     * defeats the single-flight this loop exists to provide. */
    unsigned                 wait_polled:1;
    ngx_msec_t               wait_deadline;/* give up + go to origin at this   */
    ngx_event_t              cold_wait_ev; /* poll timer for the wait loop     */
    /* This request is the cold-miss WINNER that owns the in-flight stub: it
     * went to origin and must leave a real entry OR clear the stub so waiters
     * don't block on a key that turned out non-cacheable. cold_stored = the
     * stub was resolved (a real blob was stored, or the stub was cleared); when
     * it is still 0 at request teardown the pool cleanup removes the leftover
     * stub. cold_zone is the zone to clear it in (cleanup has only the ctx). */
    unsigned                 cold_winner:1;
    unsigned                 cold_stored:1;
    ngx_http_cache_turbo_zone_t *cold_zone;
    /* CTXRDR-ADOPT-LEASE: the owner token claim() issued to THIS request when it
     * won the lease (node->refresh_owner). cold_winner says we won a lease once;
     * only this token says whether the lease live in the zone right now is still
     * ours. Every unstub() and every adoption compares it under the zone mutex.
     * 0 when this ctx never won (or inherited nothing). */
    uint64_t                 cold_owner;
    /* CTXRDR-ADOPT-LEASE (cross-node resume): claim() issues the L1 lease
     * token BEFORE the cross-node NX lock fires and the request parks
     * (NGX_AGAIN) waiting for the Redis reply. The claim_owner that carried
     * it was a stack local in the caller's frame and does not survive the
     * park/resume; stash it here at claim time so the resume path (ctx->
     * lock_done) can hand the real token to cold_mark_winner() instead of a
     * literal 0, which would leave the lease unowned and shm_unstub() a
     * permanent no-op for this key. */
    uint64_t                 pending_l1_owner;
    ngx_chain_t             *body;        /* buffered response chain        */
    ngx_chain_t             *body_last;   /* tail of body, O(1) append      */
    size_t                   body_len;
    ngx_str_t                cache_key;
    u_char                   key_hash[32];
    /* auto-Vary (v11 other half). vary_bits = the safe-axis bitmask classified
     * from the response Vary header in the header filter (>0 => store under a
     * variant key + write/refresh the marker; the body filter reads it). When a
     * request resolves to a variant via an L1 vary marker, key_hash already holds
     * the variant key. vary_nocache = the response carried a Vary the whitelist
     * refuses (*, Cookie, Authorization) => do not capture/store. */
    unsigned                 vary_nocache:1;
    ngx_int_t                vary_bits;
    /* S231-PERF-VARYLOCK: the marker key bytes, computed lock-free in the
     * prologue (marker_hash() only touches ctx->cache_key and local stack
     * memory) so the marker lookup itself can run inside the SAME critical
     * section as the main L1 lookup in access_handler, instead of its own
     * separate lock/unlock pair. Only meaningful when clcf->auto_vary. */
    u_char                   vary_marker_key[32];
    /* P3-5: set by vary_apply() when the L1 marker probe MISSED (no marker
     * node, expired-with-no-grace, or a corrupt/collided blob) while
     * clcf->auto_vary is on -- i.e. key_hash is still the BASE key, not a
     * variant key, and we do not yet know whether a peer node has already
     * classified + stored a variant for this URL in L2. Consumed by the L2
     * phase (access_l2) to decide whether an extra marker GET is worth
     * issuing before the main object GET; cleared once that consult has run
     * (or was skipped, e.g. no backend) so it can never fire twice on a
     * park/resume re-entry. Left 0 (no-op downstream) whenever auto_vary is
     * off or the L1 marker DID resolve bits -- the marker-warm path must
     * never pay this extra round trip. */
    /* COR-5(b): access_l1() found this request's L1 node carrying
     * varidx_pending (a variant-index SADD that never reached the wire at
     * store time) and consumed the bit under the zone mutex. The re-issue
     * itself is deliberately NOT done there: it allocates a pool and calls
     * connect(), neither of which belongs inside the shm critical section.
     * Each terminal arm of access_l1() instead calls
     * ngx_http_cache_turbo_varidx_reissue() immediately AFTER its own
     * unlock. Consumed exactly once (the helper clears it), so a parked-and-
     * resumed request cannot fire twice for one detection. */
    unsigned                 varidx_reissue:1;

    /* COR-5(b): the pending node's remaining physical retention
     * (stale_until - now), captured in the SAME critical section that
     * consumed varidx_reissue. Read outside the lock, so it must be a
     * by-value copy -- never re-read from the node, which may have been
     * evicted by then. */
    time_t                   varidx_reissue_ttl;

    unsigned                 vary_marker_l1_miss:1;
    /* P3-5: vary_marker_l2_tried is the park/consume in-flight flag for the
     * marker GET (set when launched, cleared once its result is consumed --
     * see access_l2_marker_get()/_consume()). vary_marker_l2_done is a
     * SEPARATE, request-lifetime, NEVER-cleared latch: the L2 marker consult
     * may only ever be attempted ONCE per request. Without it, a genuine L2
     * miss (no peer has this URL either) leaves bits==0, so vary_apply()
     * re-sets vary_marker_l1_miss=1 on EVERY re-entry of access_l1 (which
     * runs before access_l2 on every resume, including the resume of the
     * marker GET itself) -- gating solely on vary_marker_l1_miss/
     * vary_marker_l2_tried therefore re-fires the marker GET forever
     * (confirmed: an infinite parked-GET loop against a real redis-server in
     * this fix's own development, caught by the existing non-vary L2 tests
     * hanging). vary_marker_l2_done stops that: once set, marker_get() never
     * launches again for this request no matter how many times access_l1
     * re-asserts vary_marker_l1_miss. */
    unsigned                 vary_marker_l2_tried:1;
    unsigned                 vary_marker_l2_done:1;
    /* S231-L2-BACKOFF: set when the RESULT of the marker GET was a transport
     * failure (NGX_ERROR -- connect refused/timeout/malformed reply), i.e.
     * this request already paid for and proved L2 is unreachable. Read by
     * access_l2_get() to skip its own connect attempt for the object GET
     * rather than paying (and, worse, miscounting against connect_backoff's
     * fail-fast window) a second, redundant discovery of the SAME outage
     * within one request. See access_l2_marker_consume()'s field comment
     * for the concrete failure this closes. */
    unsigned                 vary_marker_l2_down:1;
    /* c-2: set by vary_apply() (NOT vary_marker_l1_miss -- the marker DID
     * resolve, from L1) when clcf->vary_marker_revalidate > 0 and the warm
     * L1 marker's resolve time is older than that window. Consulted by
     * access_l2_marker_get()/_consume() so a WARM marker also gets routed
     * through the existing L2 marker GET -- distinct from
     * vary_marker_l1_miss, which means "no marker at all". The two are
     * mutually exclusive (vary_apply only sets one or the other, never
     * both) but consumed identically by the L2 phase except for two things:
     * (1) the l2_negative_ttl memo check in marker_get() must NOT gate this
     * case (that memo answers "an L2 GET for this key missed recently",
     * which says nothing about whether an L1 marker known to exist is
     * stale), and (2) marker_consume() must not drop the landed answer just
     * because ctx->vary_marker_l1_miss is already 0 (that early-return
     * exists to protect against overriding a NEWER L1 resolution that
     * appeared mid-park; a revalidation's whole point is to let the L2
     * answer override the L1 one it is checking). Cleared by
     * marker_consume() once the GET result (hit, miss, or transport
     * failure) has been applied or fail-open has been confirmed, so it
     * never survives past the request that set it. */
    unsigned                 vary_marker_revalidate:1;
    /* c-2: persists WHY the in-flight/landed marker GET was launched across
     * a park/resume boundary. ctx->vary_marker_revalidate itself does not
     * survive a park: vary_apply() re-runs on every access_l1() re-entry
     * (including the resume of this very GET) and only re-arms it when
     * !vary_marker_l2_done, which access_l2_marker_get() has by then already
     * set -- so by the time access_l2_marker_consume() sees the landed
     * result, ctx->vary_marker_revalidate has already been reset to 0 by the
     * resume's own vary_apply() pass. Set once, at launch, only on the
     * revalidate trigger (the l1-miss trigger needs no such memory --
     * vary_marker_l1_miss itself is what consume() already keys its
     * apply-vs-drop decision on); never cleared until consume() is done with
     * it. */
    unsigned                 vary_marker_revalidate_inflight:1;
    /* P3-5: the variant this request resolved to via the L2-backed marker
     * consult, persisted so it survives a park/resume boundary. A plain
     * rewrite of ctx->key_hash does NOT survive: ngx_http_cache_turbo_
     * build_key() runs at the TOP of every access_prologue() call --
     * including every re-entry after a park -- and unconditionally
     * recomputes ctx->key_hash from ctx->cache_key, silently reverting any
     * mid-request rewrite back to the base key (confirmed: an L2 marker hit
     * correctly resolved the variant key, but the object GET launched right
     * after it, on the NEXT access_l1() entry, was observed back on the base
     * key -- see access_l2_marker_apply(), which re-derives key_hash from
     * these fields on every access_l1() entry the same way vary_apply()
     * re-derives it from the L1 marker every time, rather than depending on
     * a value surviving in ctx->key_hash across the reset). 0/bits==0 means
     * "no L2 marker resolution yet" -- indistinguishable from "resolved
     * bits=0", which cannot happen (marker_consume only sets these when
     * bits>0). */
    ngx_int_t                vary_marker_l2_bits;
    ngx_uint_t                vary_marker_l2_gen;
    /* auto-Vary PURGE generation (COR-5). Resolved from the L1 marker by
     * vary_apply and reused at store so the variant key + marker agree. Stays
     * 0 for the backend-backed purge path (variants are physically removed +
     * the marker deleted, so the keyspace resets cleanly to gen 0); only the
     * L1-only / memcached purge path bumps it (no enumerable L2 index, so an
     * old generation's variants are orphaned and age out while new requests
     * key on gen+1). variant_hash folds it ONLY when >0, so gen 0 keeps the
     * pre-COR-5 variant keys (no keyspace turnover on upgrade). */
    ngx_uint_t               vary_gen;
    /* min_uses (v15). min_uses_skip = this request is below the threshold, so the
     * header filter must NOT capture it (no store) and it runs to the origin.
     * min_uses_passed = the gate already counted this request and let it through
     * (it reached the threshold); it guards against re-counting on a park/resume
     * re-entry of the access handler (L2/NX-lock/cold-wait wake). */
    unsigned                 min_uses_skip:1;
    unsigned                 min_uses_passed:1;
    /* RFC-1 request Cache-Control (parsed once in the prologue). only_if_cached
     * (RFC 9111 §5.2.1.7): the client refuses origin contact, so a request that
     * cannot be served from L1/L2 returns 504 instead of going to the origin.
     * no_store (§5.2.1.5): do not store this request's response (the header
     * filter skips capture). Request no-cache / max-age=0 are folded into
     * ngx_http_cache_turbo_request_revalidate() and handled inline. */
    unsigned                 req_only_if_cached:1;
    unsigned                 req_no_store:1;
    /* P4: request Cache-Control + Pragma header values, resolved ONCE by
     * ngx_http_cache_turbo_resolve_req_cc() with a single walk of the request
     * header list, then read by each RFC-1 predicate (revalidate / only-if-cached
     * / no-store / freshness-bounds) instead of each re-walking the whole list
     * (the old path did that 5x per hit). data == NULL means the header is absent.
     * req_cc_resolved guards against double-resolve. nginx does NOT pre-parse a
     * request Cache-Control field (unlike cookies), so this fold is the win. */
    ngx_str_t                req_cc;
    ngx_str_t                req_pragma;
    unsigned                 req_cc_resolved:1;
    /* RFC-1 request freshness bounds (parsed once in the prologue). max_age /
     * min_fresh = -1 when absent (§5.2.1.1/§5.2.1.3). max_stale: max_stale_set
     * marks presence, max_stale_any a bare "max-stale" (accept any staleness),
     * else req_max_stale carries the value (§5.2.1.2). req_reval is set when an
     * existing entry failed the client's bounds (or no-cache/max-age=0), so the
     * cold-miss CLAIM_FRESH path must NOT re-serve the raced-in fresh entry. */
    time_t                   req_max_age;
    time_t                   req_min_fresh;
    time_t                   req_max_stale;
    unsigned                 req_max_stale_set:1;
    unsigned                 req_max_stale_any:1;
    unsigned                 req_reval:1;
    /* PERF (P2): set iff the client sent ANY of max-age/min-fresh/max-stale, i.e.
     * the freshness bounds can actually change the serve verdict. When unset the
     * per-hit req_serve_verdict/bounds block on the lookup fast path is dead work
     * (all three bounds are -1/absent => fresh serves, stale serves) and is
     * skipped. only-if-cached is NOT folded here: it is handled at :2998/:3511. */
    unsigned                 has_req_bounds:1;
    /* RFC 5861 §4 / RFC-2 stale-if-error serve-on-error (CTB4). On a lookup that
     * finds the entry EXPIRED (past its stale window) but still inside the blob's
     * serve-on-error window (created + sie_ttl), we DECLINE to origin yet stash a
     * snapshot of the stale blob here (sie_snap, r->pool). If the origin
     * revalidation then returns 5xx, the header+body filters REPLACE the error
     * response with this snapshot (X-Cache: STALE-IF-ERROR) instead of surfacing
     * the failure. No node field is needed: eviction is pure-LRU (no TTL reaper),
     * so the expired node survives on its own; arming at access time is enough. */
    unsigned                 sie_armed:1;     /* a within-SIE snapshot is stashed */
    unsigned                 sie_serving:1;   /* filters replacing error w/ snap  */
    unsigned                 sie_body_sent:1; /* snapshot last_buf already emitted */
    /* S231-SIE-MIDBODY: set the moment the body filter has forwarded ANY
     * non-empty buffer downstream on the capture/forward path (i.e. bytes the
     * client may already have received). This is the pre-flush oracle: once
     * set, a mid-body origin death can no longer be rescued -- the client
     * already has an unknown-length prefix of the truncated response and
     * splicing the snapshot body in now would produce a corrupt concatenation,
     * not a fix. ngx_http_cache_turbo_forward_body() is the single set site --
     * every downstream exit on the capture path routes through it; see the
     * rescue-site comment in the body filter for why that is exhaustive. */
    unsigned                 sie_flushed:1;
    u_char                  *sie_snap;        /* blob bytes, any age               */
    size_t                   sie_snap_len;
    /* PERF (S231-PERF-SIEARM): the L1 arm pins the blob under the zone mutex
     * (PERF-7 style) instead of copying it out, and registers a pool cleanup
     * (ngx_http_cache_turbo_blob_ref_cleanup, out-param NULL -- nothing here
     * needs to drop the reference early) that releases the shm reference once
     * the request pool is destroyed; sie_snap then points straight into the
     * shm slab. The L2 arm instead copies ctx->l2_blob into a fresh r->pool
     * buffer and points sie_snap at that copy -- no shm reference exists on
     * that path, so there is nothing to release. Either way this
     * replaced a memcpy of the whole blob under the ZONE MUTEX on every
     * expired-but-within-SIE-window entry, serialising concurrent workers on
     * a 1 MiB-default (configurable) copy exactly during the outage this
     * feature exists to smooth over. */
    u_char                  *sie_body;        /* body slice inside sie_snap        */
    size_t                   sie_body_len;

#if defined(NGX_HTTP_CACHE_TURBO_TEST_FAULTS) \
    && NGX_HTTP_CACHE_TURBO_TEST_FAULTS
    /* AUD-SIE-BODY: count of incoming `in` buffers left UNCONSUMED (buf->pos !=
     * buf->last) at the point the sie_serving block in the body filter returns,
     * summed across both its exits. With the consume-loop fix in place this is
     * always 0; reverting the fix leaves the upstream's error-body buffers
     * un-advanced and this counts them.
     *
     * NOT exposed as a response header: by the time the body filter runs,
     * ngx_http_next_header_filter() has already returned for this request (the
     * sie_serving header-filter exit calls it unconditionally and synchronously
     * -- nginx's header filter chain serializes r->headers_out.headers into the
     * wire buffer inside that call, with no postponement contract), so a header
     * written from here would be invisible to the client and would always read
     * 0. Logged instead via ngx_log_debug1() with the greppable
     * "cache_turbo: test_sie_unconsumed=" token; a runtime test with
     * TEST_CT_ERRLOG=debug reads it out of logs/error.log, bracketed by byte
     * offset to attribute the line to one request. */
    ngx_uint_t                test_sie_unconsumed;
#endif

    /* P6/O4.3 circuit-breaker fallback snapshot. Taken at the SAME two
     * fall-through sites that arm SIE (L1 past its stale window, L2 blob past
     * rem_stale), but under a DIFFERENT and much wider rule: SIE is armed only
     * inside `created + sie_ttl`, whereas the breaker serves a body of ANY age
     * once the origin is known to be down. Serving a week-old page beats
     * serving 503, and the operator opted in by enabling the breaker.
     *
     * ⚠ Deliberately a SEPARATE snapshot rather than widening sie_armed. The
     * SIE window is a response-driven RFC 5861 contract consumed by the header
     * filter on an origin ERROR; this one is an operator-driven policy consumed
     * by the access handler BEFORE any origin contact. Folding them would let a
     * breaker config silently widen stale-if-error for responses that never
     * asked for it.
     *
     * Both point into r->pool (a copy taken under the zone mutex), so no shm
     * reference is held and ngx_http_cache_turbo_serve() is called with
     * ref_data = NULL. Only taken when the breaker is actually enabled --
     * threshold == 0 skips the memcpy entirely, so "breaker off" stays free. */
    unsigned                 brk_armed:1;     /* a breaker fallback is stashed  */

    /* P6/O4.3-c: arming was ATTEMPTED, independent of whether the fallback is
     * still held. brk_armed cannot serve as the once-per-request guard on its
     * own any more: the gate clears it when it drops a pin nothing can consume,
     * and a PASS request does not stop there -- it falls through to claim() and
     * cold_wait(), whose every re-poll re-enters this handler from the top.
     * Guarding on brk_armed alone would then re-register a pool cleanup and
     * re-acquire the blob on each poll, for the whole lock_timeout. This latch
     * is set once and never cleared, which is what sie_armed relies on too. */
    unsigned                 brk_arm_done:1;  /* arming already attempted       */
    u_char                  *brk_snap;        /* blob bytes, any age            */
    size_t                   brk_snap_len;
    /* PERF: when non-NULL, brk_snap points into the shm slab and this holds the
     * pinned blob for ngx_http_cache_turbo_serve()'s ref_data (the pool cleanup
     * drops the reference once the response drains). NULL means brk_snap is an
     * r->pool buffer owned by somebody else -- the L2 path -- and no reference
     * is held. Mirrors the fresh/stale serve paths rather than copying: the L1
     * arming used to memcpy the whole blob under the ZONE MUTEX on every
     * enabled request that found an expired entry, which serialises concurrent
     * workers on a 1 MiB-default (configurable) copy exactly during the outage
     * this feature exists to smooth over. */
    u_char                  *brk_ref;         /* pinned shm blob, or NULL       */

    /* P6/O4.3-c: the cleanup record that owns brk_ref's reference, so the
     * breaker gate can DROP that reference as soon as its verdict rules out a
     * fallback serve, instead of holding it until the request pool is
     * destroyed. Most armed requests fall through to the origin, and on a slow
     * upstream those pins accumulate: an evictor can then unlink an entry's LRU
     * metadata and still not reclaim its blob, so the zone drains without
     * freeing space (Codex F3, PR #135). NULL once dropped or never armed.
     *
     * void * because this header is the public one: the layout of
     * ngx_http_cache_turbo_blob_cln_t lives in
     * ngx_http_cache_turbo_internal.h, and access.c is the only file that
     * dereferences this. */
    void                    *brk_cln;

    /* P6/O4.3: the pre-origin gate's verdict, latched on first consult.
     *
     * ⚠ THE GATE MUST BE CONSULTED AT MOST ONCE PER REQUEST, and these two
     * fields are what enforces it. The access handler is re-entered from the
     * TOP on every park/resume (the L2 GET park, the v4-2 Redis NX lock park,
     * and each cold_wait() re-poll), so an unguarded gate calls
     * _breaker_state() several times for one request.
     *
     * That is not merely wasteful, it is the wedge the whole design exists to
     * avoid. _breaker_state() is not a pure getter: it PROMOTES exactly one
     * caller per open window to HALF_OPEN, and it returns HALF_OPEN only to
     * that promoter -- every later call, including a later call by the SAME
     * request, is told OPEN (shm.c:1188). So a request promoted to probe that
     * then parks would, on its resume, be handed OPEN, get answered from cache
     * or 503'd, and never reach the origin. Nothing would record an outcome,
     * and the breaker would stay open until the lease expired -- burning one
     * probe per window forever, which is exactly the failure the HALF_OPEN
     * pass-through is designed to prevent.
     *
     * Latching also keeps the verdict COHERENT across a resume: a request must
     * not be told PASS before parking and SERVE afterwards because a different
     * worker tripped the breaker meanwhile. It committed to going to the
     * origin; it goes.
     *
     * Same idempotence discipline as l2_miss_counted, min_uses_passed and
     * sie_armed, all of which guard the identical re-entry hazard. */
    unsigned                 brk_consulted:1; /* gate already ran this request  */
    ngx_uint_t               brk_action;      /* latched BRK_ACT_* verdict      */
    ngx_uint_t               brk_state;       /* latched BREAKER_* state        */

    /* P6/O4.3: the probe lease token, non-zero ONLY on the request that won the
     * OPEN -> HALF_OPEN promotion. Handed to _breaker_record() in the header
     * filter so that exactly that request's origin outcome resolves the lease;
     * every other request passes NO_PROBE and cannot. */
    ngx_uint_t               brk_probe;       /* lease token, 0 = not the probe */
    /* Per-request serve outcome for $cache_turbo_status / access logging. One of
     * NGX_HTTP_CACHE_TURBO_ST_*; defaults to ST_MISS (0) via pcalloc and is
     * overridden to HIT/STALE at the X-Cache emit site, BYPASS on the
     * auto-classify / cache_turbo_bypass paths, EXPIRED when a cached entry is
     * found past its serveable window (L1 or L2) and refetched from origin. */
    ngx_uint_t               status;
    /* S7.2: unfolded per-request serve reason for $cache_turbo_serve_reason.
     * One of NGX_HTTP_CACHE_TURBO_SR_*; defaults to SR_NONE (0) via pcalloc.
     * Set at the same capture points as `status` above but WITHOUT folding
     * STALE/STALE-IF-ERROR/STALE-BREAKER together, plus the breaker's local
     * 503 (which never touches `status` -- see breaker_unavailable()). */
    ngx_uint_t               serve_reason;
} ngx_http_cache_turbo_ctx_t;


/* Must stay default-visibility: the auto-generated
 * ngx_http_cache_turbo_module_modules.c (nginx's own build glue, not one of
 * our TUs) takes this struct's address into the ngx_modules[] array that
 * nginx's dynamic-module loader resolves by dlsym() name. See the pragma
 * block at the top of this header for the visibility-scoping rationale. */
extern ngx_module_t  ngx_http_cache_turbo_module
    __attribute__((visibility("default")));


/* ---- shm.c ---- */
ngx_int_t ngx_http_cache_turbo_shm_init_zone(ngx_shm_zone_t *zone, void *data);

/* PERF-7 zero-copy serve refcount. acquire() pins a blob for an in-flight serve
 * and MUST be called with shpool->mutex held (same critical section as the
 * lookup that produced `data`). release() is the request-pool cleanup: it drops
 * the ref LOCK-FREE (C1) and, only when that was the very last reference — the
 * owning node having already detached the blob — takes the mutex itself to
 * return the slab. It must therefore still never be called with the zone mutex
 * held. `data` is ngx_http_cache_turbo_node_t.data (the blob ptr, never NULL). */
void ngx_http_cache_turbo_blob_acquire(u_char *data);
void ngx_http_cache_turbo_blob_release(ngx_http_cache_turbo_zone_t *z,
    u_char *data);

/* S8: re-splice a node on access, promoting it to the PROTECTED segment on its
 * second touch. THE single implementation of the promotion rule -- all three
 * re-splice sites (fresh HIT, stale HIT, L13 memo consult) call this, so the
 * rule cannot drift between them.
 *
 * `protected_pct` is the effective cache_turbo_scan_resistant setting: 0 means
 * the feature is OFF and the node simply re-heads within probation, which is
 * byte-for-byte the pre-S8 flat LRU. The P1 1-second coarse gate is applied
 * INSIDE -- callers must not pre-filter on last_access, or the two gates drift.
 *
 * Caller holds shpool->mutex. */
void ngx_http_cache_turbo_shm_touch_lru(ngx_http_cache_turbo_zone_t *z,
    ngx_http_cache_turbo_node_t *ctn, time_t now, ngx_uint_t protected_pct,
    uint32_t hash);

/* P4-1a: W-TinyLFU frequency sketch. Both hold the shpool mutex via the
 * caller, and both tolerate an unallocated sketch (bump is a no-op, estimate
 * returns 0). See the sketch field block in the shctx above.
 *
 * STAGE 1 OF 2 -- nothing in the tree reads the estimate yet; these exist so
 * stage 2's admission test has data to decide on. */
void ngx_http_cache_turbo_shm_sketch_bump(ngx_http_cache_turbo_zone_t *z,
    uint32_t hash);
ngx_uint_t ngx_http_cache_turbo_shm_sketch_estimate(
    ngx_http_cache_turbo_zone_t *z, uint32_t hash);

/* Remove a leftover cold-miss STUB (v10): drops the node ONLY if it is still a
 * stub (len == 0), so a real entry stored by someone else is never touched.
 * Used when a cold-miss winner's response turned out non-cacheable.
 *
 * CTXRDR-ADOPT-LEASE: `owner` is the token claim() issued to the caller. The
 * lease is released ONLY if the node still carries that exact token, so a
 * request whose lease was re-issued to someone else cannot clear the current
 * holder's. Pass the ctx's cold_owner; 0 never matches a live lease. */
void ngx_http_cache_turbo_shm_unstub(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, uint64_t owner);

/* CTXRDR-ADOPT-LEASE: does `owner` still hold the live single-flight lease for
 * this key? Checked under the zone mutex against node->refresh_owner, so the
 * answer reflects the zone at the instant of the call rather than any
 * request-local memory of having won. Returns NGX_OK when the lease is ours and
 * still live, NGX_DECLINED otherwise (re-leased, resolved, evicted, or never
 * ours). The ONLY sound basis for adopting a stub across an internal redirect. */
ngx_int_t ngx_http_cache_turbo_shm_owns(ngx_http_cache_turbo_zone_t *z,
    u_char *key_hash, uint32_t hash, uint64_t owner);

/* P6/O4.1 circuit breaker (per-zone, lock-free -- see the shctx field block).
 *
 * O4.3 added the probe TOKEN to both calls. `*probe` is an out-parameter on
 * _breaker_state() and an in-parameter on _breaker_record(); NGX_HTTP_CACHE_
 * TURBO_BREAKER_NO_PROBE means "this caller does not own a probe lease".
 *
 * ⚠ Only the request that WON the OPEN -> HALF_OPEN promotion receives a
 * non-zero token, and only that token may resolve HALF_OPEN. Without it any
 * unrelated origin response completing during the open window could close (or
 * re-open) a lease it knows nothing about: a request that started before the
 * trip reports "origin fine" and releases the herd toward a still-dead origin,
 * and a promoted probe that ends up served from a peer's L2 fill leaves the
 * breaker with no outcome at all. Pass NO_PROBE from every non-probe site.
 *
 * ⚠ The token is the promotion's GENERATION, unpacked out of breaker_state --
 * NOT the probe stamp an earlier revision used. Two leases promoted
 * in the same wall-clock second carry the same stamp, so a stamp token could
 * not tell a superseded probe from the current one (O4.3-c/F1). The generation
 * is bumped by every promotion and CASed as part of the same atomic word, so a
 * stale token cannot resolve a lease that replaced it. */
ngx_uint_t ngx_http_cache_turbo_shm_breaker_state(
    ngx_http_cache_turbo_zone_t *z, time_t open_for, ngx_uint_t *probe);
void ngx_http_cache_turbo_shm_breaker_record(ngx_http_cache_turbo_zone_t *z,
    ngx_uint_t success, ngx_uint_t threshold, time_t window, ngx_uint_t probe);
const char *ngx_http_cache_turbo_shm_breaker_state_str(ngx_uint_t state);


/* ---- swr.c ---- */
time_t    ngx_http_cache_turbo_stale_ttl(time_t fresh_ttl, ngx_int_t stale_mult);
time_t    ngx_http_cache_turbo_add_ttl_clamped(time_t base, time_t delta);
ngx_int_t ngx_http_cache_turbo_should_refresh(u_char *key_hash,
    time_t fresh_until, time_t stale_window, ngx_int_t beta_milli);


/* ---- autotune.c (live autotune within preset bands, v4-3) ---- */

/* Record one origin-regeneration cost sample (request_time in ms) into the zone's
 * running cost accumulator. Called on the origin→cache store path only (never the
 * cheap L2→L1 fill), so the average reflects real origin latency. Lock-free
 * (two atomic adds); ms < 0 is clamped to 0. */
void ngx_http_cache_turbo_autotune_record_cost(ngx_http_cache_turbo_zone_t *z,
    ngx_msec_int_t ms);

/* Throttled per-zone recompute. At most once per `interval` seconds per worker
 * (guarded by z->sh->autotune_next): reads the L1 stats delta since the last
 * tick, derives a target beta from the average miss-cost, applies the qualify /
 * churn gates, and publishes the global-clamped verdict to z->sh->autotuned_beta
 * (0 when the zone doesn't qualify or there is too little data). The request path
 * re-clamps that verdict to the location's preset band. Cheap to call every
 * request — the heavy path runs at most once per interval. */
void ngx_http_cache_turbo_autotune_maybe(ngx_http_cache_turbo_zone_t *z,
    time_t interval);

/* Force an immediate recompute over the window since the last snapshot, ignoring
 * the interval throttle (does not disturb the throttle schedule). Backs the admin
 * "recompute now" command (`?autotune=1`) — an operator escape hatch, and what
 * makes the autotune tests deterministic without waiting on the interval. */
void ngx_http_cache_turbo_autotune_force(ngx_http_cache_turbo_zone_t *z);


/* ---- redis.c (L2, v2b) ---- */

/* Default key prefix for L2 entries (overridable with prefix=). */
#define NGX_HTTP_CACHE_TURBO_REDIS_PREFIX  "ct:"

/* Build the L2 redis key for a cache entry into buf (must hold prefix.len +
 * 64). Returns the byte length written. Key = prefix + lowercase hex of the
 * 32-byte key hash, so it is stable and shareable across nodes. */
size_t ngx_http_cache_turbo_redis_key(ngx_str_t *prefix, u_char *key_hash,
    u_char *buf);

/* PERF-1/2: drop many L2 keys in ONE connection. Pipelines chunked variadic
 * UNLINK commands (each UNLINK deletes up to a fixed cap of keys and returns a
 * single integer reply) instead of one fire-and-forget connection per key, so a
 * large tag/all purge can no longer open thousands of sockets at once. Key
 * bytes are copied into the op pool, so the caller's array need not outlive the
 * call. No-op when L2 is disabled or nkeys == 0. */
void ngx_http_cache_turbo_redis_del_many(ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_str_t *keys, ngx_uint_t nkeys);

/* AUD-SCAN1: outcome of a SCAN-del keyspace walk, handed to the completion
 * callback so it can tell a FINISHED walk from an ABANDONED one. Before this
 * existed every terminal path — cursor 0, read timeout, malformed reply —
 * called the callback identically, so a half-purged L2 was reported as a clean
 * success. NULL for the SMEMBERS path (which walks nothing).
 *
 *   status  NGX_OK    - cursor returned to 0: the whole keyspace was walked
 *           NGX_ABORT - the page cap or scan_deadline was hit: purge is
 *                       INCOMPLETE by policy (see `deadline` below for which)
 *           NGX_ERROR - timeout / malformed reply / alloc failure: INCOMPLETE
 *   pages   SCAN pages consumed (>= 1 once any reply was parsed)
 *   blocks  live pool blocks held by the walk at finish. Diagnostic only, and
 *           only reported under TEST_FAULTS: it is the oracle proving per-page
 *           allocations are released per page (constant in `pages`) rather than
 *           accumulating in the op pool for the whole walk. Kept unconditional
 *           in the struct so the plumbing has no #if seams.
 *   deadline S231-L2-SCANTIME: 1 when NGX_ABORT was reached via the wall-clock
 *           scan_deadline= rather than the page cap — the observable marker
 *           that distinguishes the two ABORT causes for callers/tests. */
typedef struct {
    ngx_int_t   status;
    ngx_uint_t  pages;
    ngx_uint_t  blocks;
    unsigned    deadline:1;
} ngx_http_cache_turbo_redis_walk_t;

/* Completion callback for a SMEMBERS fetch: invoked once with the set members
 * (pointing into transient buffers — copy what must outlive the call) BEFORE
 * the request is finalized. Must produce the HTTP response and return the rc to
 * finalize with. Called with nmembers==0 on an empty/missing set or any error,
 * so the response path is uniform. `walk` is non-NULL only on the SCAN-del
 * path; a callback that ignores it treats an abandoned walk as a success. */
typedef ngx_int_t (*ngx_http_cache_turbo_redis_members_pt)(
    ngx_http_request_t *r, void *data, ngx_str_t *members,
    ngx_uint_t nmembers, const ngx_http_cache_turbo_redis_walk_t *walk);

/* Sync-on-L1-miss GET. Issues GET <key> and parks the request (count++,
 * NGX_AGAIN) until the reply arrives; the read handler stores the result in
 * ctx (l2_done + l2_result + l2_blob) and resumes the phase engine. Returns:
 *   NGX_AGAIN    - parked, caller must return NGX_AGAIN to suspend the request
 *   NGX_DECLINED - L2 disabled or could not start; caller proceeds to origin
 * On re-entry after the reply, the caller inspects ctx->l2_result. */
ngx_int_t ngx_http_cache_turbo_redis_get(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, ngx_http_cache_turbo_ctx_t *ctx);

/* Build the cross-node lock key "<prefix>lock:<64 hex of key hash>" into buf
 * (must hold prefix.len + sizeof("lock:")-1 + 64). Returns bytes written. */
size_t ngx_http_cache_turbo_redis_lockkey(ngx_str_t *prefix, u_char *key_hash,
    u_char *buf);


/* ---- backend vtables (v4-1, #6) ---- */

/*
 * L1 local-store backend. Synchronous in-process tier. `lookup` returns the live
 * node so the caller (holding the zone mutex) can read its fields and run the SWR
 * dice itself — that is why the stale/serve-stale control flow stays in the
 * access handler rather than being hidden inside a fused get(). Today's only
 * driver is shm; a future disk/mmap local tier would slot in behind this struct.
 */
struct ngx_cache_turbo_l1_backend_s {
    ngx_str_t   name;

    ngx_http_cache_turbo_node_t *(*lookup)(ngx_http_cache_turbo_zone_t *z,
        u_char *key_hash, uint32_t hash);
    ngx_int_t  (*store)(ngx_http_cache_turbo_zone_t *z, u_char *key_hash,
        uint32_t hash, u_char *data, size_t len,
        time_t fresh_ttl, time_t stale_ttl);

    /* Atomic "decide-then-write" store (AUD-L2-PROMOTE-RACE / AUD-5XX-CTA).
     * Modeled on `claim`, NOT on `store`: the predicate is evaluated and the
     * write performed under ONE hold of the zone mutex, closing the
     * check-then-act window a separate lookup-then-store pair leaves open.
     *
     * Returns:
     *   NGX_OK       -- predicate passed, entry written (as store() today).
     *   NGX_DECLINED -- predicate REFUSED the write; nothing was modified.
     *                   This is a NORMAL outcome, not an error -- callers
     *                   must treat it as a distinct third value, never as
     *                   NGX_ERROR and never silently as NGX_OK.
     *   NGX_ERROR    -- predicate passed but the write itself failed
     *                   (alloc/evict), same meaning as store() returning
     *                   NGX_ERROR today.
     *
     * predicate selects which refusal rule gates the write:
     *   NGX_HTTP_CACHE_TURBO_STORE_IF_NEWER -- refuse iff the resident node
     *     is a real entry (kind == ENTRY, len > 0) strictly fresher than the
     *     value about to be written (ctn->fresh_until > now + fresh_ttl).
     *     Used by the L2 promote path: never let a parked, slow L2 reply
     *     displace a newer origin response that landed while it was parked.
     *   NGX_HTTP_CACHE_TURBO_STORE_IF_ABSENT_OR_DEAD -- refuse iff the
     *     resident node is a real entry (kind == ENTRY, len > 0) still
     *     within its stale window (stale_until == 0, meaning forever, OR
     *     now < stale_until). Used by the 5xx store path: never let an
     *     error response overwrite a still-servable good body. */
    ngx_int_t  (*store_if)(ngx_http_cache_turbo_zone_t *z, u_char *key_hash,
        uint32_t hash, u_char *data, size_t len,
        time_t fresh_ttl, time_t stale_ttl, ngx_uint_t predicate);

    ngx_int_t  (*purge_key)(ngx_http_cache_turbo_zone_t *z, u_char *key_hash,
        uint32_t hash);
    ngx_uint_t (*purge_all)(ngx_http_cache_turbo_zone_t *z);
    void       (*stats)(ngx_http_cache_turbo_zone_t *z,
        ngx_http_cache_turbo_stats_t *out);

    /* Cold-miss single-flight claim (v10). Atomically (under the zone mutex)
     * decide whether this request regenerates the key or waits for someone else.
     * Returns CLAIM_WINNER (took/created the in-flight stub — go to origin),
     * CLAIM_LOSER (someone else is in flight — wait), or CLAIM_FRESH (a real
     * fresh entry raced in — re-serve via lookup). lock_ttl bounds the stub.
     *
     * CTXRDR-ADOPT-LEASE: on CLAIM_WINNER, *owner receives the zone-wide token
     * identifying THIS request as the lease holder; it must be stored in the ctx
     * and handed back to unstub(). Set to 0 on every non-winner return. Callers
     * must not treat a past win as current ownership -- ask shm_owns(). */
    ngx_int_t  (*claim)(ngx_http_cache_turbo_zone_t *z, u_char *key_hash,
        uint32_t hash, time_t lock_ttl, uint64_t *owner);

    /* min_uses miss counter (v15). Atomically (under the zone mutex) count one
     * cold miss for the key and decide whether it has now been requested enough
     * times to be worth caching. Returns NGX_OK (>= min_uses — proceed to the
     * cold-miss/store path) or NGX_DECLINED (still below — go to origin, do not
     * store). A node holding a real body (len > 0) or an in-flight stub returns
     * NGX_OK without counting (a refresh of an already-cached key is never
     * re-gated). Only called when min_uses > 1. */
    ngx_int_t  (*count_miss)(ngx_http_cache_turbo_zone_t *z, u_char *key_hash,
        uint32_t hash, ngx_int_t min_uses, time_t min_uses_window);

    /* S231-PERF-MISSLOCKS: merged count_miss()+claim() -- see
     * ngx_http_cache_turbo_shm_resolve_miss()'s comment for the exact
     * contract. Only called when min_uses > 1 AND cache_turbo_lock is on
     * (the case where count_miss() and claim() would otherwise run
     * back-to-back under two separate mutex holds on the same request pass). */
    ngx_int_t  (*resolve_miss)(ngx_http_cache_turbo_zone_t *z,
        u_char *key_hash, uint32_t hash, ngx_int_t min_uses, time_t min_uses_window,
        time_t lock_ttl, uint64_t *owner, ngx_int_t *count_miss_rc,
        u_char **fresh_data, size_t *fresh_len);

    /* L2 negative memo (L13). Both halves take the zone mutex internally.
     *
     * l2_neg_check: NGX_DECLINED if a live memo says "L2 missed this key
     * recently, skip the GET"; NGX_OK if the caller should consult L2 (no memo,
     * memo expired, or a real body/stub exists -- those are never memoed).
     *
     * l2_neg_set: record a memo for `ttl` seconds after an L2 GET missed.
     * Best-effort: allocates a counter node if none exists and silently does
     * nothing when the slab is full (losing a memo costs a round-trip, never
     * correctness). Never overwrites a node that holds a body (len > 0) or an
     * in-flight stub -- neither ever consults L2 on the memo path.
     *
     * Only called when l2_negative_ttl > 0. */
    ngx_int_t  (*l2_neg_check)(ngx_http_cache_turbo_zone_t *z, u_char *key_hash,
        uint32_t hash);
    void       (*l2_neg_set)(ngx_http_cache_turbo_zone_t *z, u_char *key_hash,
        uint32_t hash, time_t ttl);

    /* P5-4: 304 freshening. Bump a resident entry's fresh_until/stale_until
     * IN PLACE (no body touched, no re-alloc) when a revalidation came back
     * 304 Not Modified -- the origin's own confirmation that the stored body
     * is still correct. Unlike store()/store_if(), this never creates a new
     * node: a 304 with no matching resident entry has nothing to confirm and
     * must not fabricate one (NGX_DECLINED).
     *
     * Returns:
     *   NGX_OK       -- resident entry found (kind == ENTRY, len > 0) and
     *                    its freshness window extended.
     *   NGX_DECLINED -- no resident entry, or a stub/counter node -- nothing
     *                    to freshen. Not an error; the caller falls back to
     *                    the ordinary "304 with nothing to extend" case
     *                    (log and move on, same as before this existed).
     *
     * fresh_ttl/stale_ttl are seconds from now, same units and same-origin
     * meaning as store()'s -- the caller derives them from the revalidation
     * response's own Cache-Control/Expires (or the location's configured
     * `valid`/`stale` if the 304 carried none), never from the stale entry's
     * OLD ttls, which would compound rather than refresh. */
    ngx_int_t  (*freshen)(ngx_http_cache_turbo_zone_t *z, u_char *key_hash,
        uint32_t hash, time_t fresh_ttl, time_t stale_ttl);
};

#define NGX_HTTP_CACHE_TURBO_CLAIM_WINNER  0
#define NGX_HTTP_CACHE_TURBO_CLAIM_LOSER   1
#define NGX_HTTP_CACHE_TURBO_CLAIM_FRESH   2

/* store_if() predicates (AUD-L2-PROMOTE-RACE / AUD-5XX-CTA) -- see the L1
 * vtable `store_if` comment for the exact refusal rule each one applies. */
#define NGX_HTTP_CACHE_TURBO_STORE_IF_NEWER            0
#define NGX_HTTP_CACHE_TURBO_STORE_IF_ABSENT_OR_DEAD   1


extern ngx_cache_turbo_l1_backend_t  ngx_http_cache_turbo_shm_backend;


/*
 * L2 remote-driver backend. Asynchronous — `get` and `purge_tag` park the
 * request (count++, NGX_AGAIN) and resume it when the reply lands. redis is the
 * only driver today; memcached / disk slot in behind the same struct later. A
 * driver that cannot perform an op leaves that member NULL (e.g. memcached has
 * no atomic tag set, so its `purge_tag`/`tag_add` would be NULL). `lock`/
 * `unlock` are the v4-2 multi-node single-flight slots (SET NX PX); NULL until
 * then so v4-2 only fills the functions, never re-touches this struct.
 */
struct ngx_cache_turbo_backend_s {
    ngx_str_t   name;

    ngx_int_t  (*get)(ngx_http_request_t *r,
        ngx_http_cache_turbo_loc_conf_t *clcf,
        ngx_http_cache_turbo_ctx_t *ctx);
    /* fresh_ttl is the object's fresh lifetime (metadata/logging only --
     * NOT the L2 key's expiry). retain_ttl is how long the L2 key itself
     * must survive: the full serveable window (fresh ∪ stale ∪ any wider
     * retention the caller has decided on). The caller computes retain_ttl;
     * the backend must use it as-is and must NOT re-derive it from
     * fresh_ttl. */
    void       (*set)(ngx_http_request_t *r,
        ngx_http_cache_turbo_loc_conf_t *clcf, u_char *key_hash,
        u_char *blob, size_t blob_len, time_t fresh_ttl, time_t retain_ttl);
    void       (*del)(ngx_http_cache_turbo_loc_conf_t *clcf, u_char *key_hash);
    void       (*del_raw)(ngx_http_cache_turbo_loc_conf_t *clcf, u_char *key,
        size_t key_len);
    size_t     (*tagkey)(ngx_str_t *prefix, u_char *name, size_t name_len,
        u_char *buf);
    /* COR-5(b): returns NGX_OK once the op is HANDED TO the transport (the
     * write is still fire-and-forget -- NGX_OK is NOT an acknowledgement from
     * the server) and NGX_ERROR when it was DROPPED before the wire: an armed
     * S231 connect-backoff window, a failed connect, or an alloc failure. The
     * distinction exists so the auto-Vary variant-index caller can mark the
     * L1 node varidx_pending and re-issue on a later hit, instead of silently
     * losing the index entry and leaving a purged base serving a stale
     * variant until its own TTL. */
    ngx_int_t  (*tag_add)(ngx_http_cache_turbo_loc_conf_t *clcf,
        u_char *key_hash, u_char *name, size_t name_len, time_t ttl);
    /* L9: batched tag_add (one op for N tags). NULL on a backend without tag
     * support, exactly like tag_add -- callers must check it before use.
     * Same NGX_OK/NGX_ERROR launch contract as tag_add. */
    ngx_int_t  (*tag_add_many)(ngx_http_cache_turbo_loc_conf_t *clcf,
        u_char *key_hash, ngx_str_t *names, ngx_uint_t nnames, time_t ttl);
    ngx_int_t  (*purge_tag)(ngx_http_request_t *r,
        ngx_http_cache_turbo_loc_conf_t *clcf, u_char *name, size_t name_len,
        ngx_http_cache_turbo_redis_members_pt cb, void *data);

    /* Purge the whole L2 keyspace (v4-2): SCAN MATCH <prefix>* + DEL each, then
     * invoke cb(r, data, NULL, 0) to emit the response. Parks the request. */
    ngx_int_t  (*scan_del)(ngx_http_request_t *r,
        ngx_http_cache_turbo_loc_conf_t *clcf,
        ngx_http_cache_turbo_redis_members_pt cb, void *data);

    /* Cross-node dogpile (v4-2): async SET <prefix>lock:<hex> <owner> NX PX
     * <ttl*1000>. Parks the request (count++, NGX_AGAIN); on reply ctx->lock_*
     * is set (NGX_OK = acquired). NGX_DECLINED synchronously if it could not
     * start (L2 down) — caller falls back to single-box regen. `unlock` stays
     * NULL: the lock is released by PX expiry, never by owner (see history.md
     * v4-2 — early unlock would re-open the single-flight window). */
    ngx_int_t  (*lock)(ngx_http_request_t *r,
        ngx_http_cache_turbo_loc_conf_t *clcf,
        ngx_http_cache_turbo_ctx_t *ctx, time_t ttl);
    ngx_int_t  (*unlock)(ngx_http_cache_turbo_loc_conf_t *clcf, u_char *key_hash,
        ngx_str_t *owner);
};


extern ngx_cache_turbo_backend_t  ngx_http_cache_turbo_redis_backend;
extern ngx_cache_turbo_backend_t  ngx_http_cache_turbo_memcached_backend;

/* Preset bands (v3-2): defined in ngx_http_cache_turbo_module.c, indexed by
 * ngx_http_cache_turbo_loc_conf_t.preset. Shared with
 * ngx_http_cache_turbo_conf.c's merge_loc_conf. */
extern const ngx_http_cache_turbo_band_t  ngx_http_cache_turbo_bands[];

/* Cross-file (MAINT-C1): ngx_http_cache_turbo_conf.c holds merge_loc_conf and
 * the redis_conf/memcached_conf directive handlers, split out of
 * ngx_http_cache_turbo_module.c for size. These were `static` in module.c and
 * are now shared; new module.c call sites of breaker_should_consult /
 * redis_build_ssl are unaffected -- only the storage class changed. */
char *ngx_http_cache_turbo_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
char *ngx_http_cache_turbo_redis_conf(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_cache_turbo_memcached_conf(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
/* ngx_http_cache_turbo_redis_build_ssl moved to ngx_http_cache_turbo_conf.c
 * alongside its only caller (merge_loc_conf) in MAINT-SPLIT step H and is
 * static there now. */
ngx_uint_t ngx_http_cache_turbo_breaker_should_consult(
    ngx_http_cache_turbo_loc_conf_t *clcf);


/* ---- module.c: response helpers shared with admin.c ---- */
ngx_int_t ngx_http_cache_turbo_send_body(ngx_http_request_t *r,
    ngx_uint_t status, ngx_str_t *body, const char *ctype, size_t ctype_len);
ngx_int_t ngx_http_cache_turbo_send_json(ngx_http_request_t *r,
    ngx_uint_t status, ngx_str_t *body);

/* One-shot digest convenience for a single contiguous input (module.c).
 * Returns NGX_OK on success, NGX_ERROR on failure. */
ngx_int_t ngx_http_cache_turbo_digest(const void *data, size_t len,
    u_char out[32]);

/* State carried through an async tag purge from the admin handler (or the
 * variant-index purge in module.c) to the SMEMBERS completion callback. */
typedef struct {
    ngx_http_cache_turbo_loc_conf_t  *clcf;
    ngx_http_cache_turbo_zone_t      *zone;
    ngx_str_t                         tag;    /* copied into r->pool */

    /* c-1: set by the COR-5 auto-Vary caller (purge_auto_vary), clear on the
     * admin ?tag= path.
     *
     * ⚠ Currently WRITE-ONLY: it used to gate the "complete":false reply, but
     * SILENT-INDEX-DROP(c) extended that report to the by-tag path too, and
     * which counter feeds pending_at_launch is now decided at the CALL SITE
     * (each caller snapshots its own), so the completion needs no caller
     * check. Kept because it is the only thing distinguishing the two callers
     * in the completion's context, and the next path-specific behaviour will
     * want it -- not because anything reads it today. Delete it, rather than
     * inventing a use, if that stays true. */
    unsigned                           is_auto_vary:1;

    /* SILENT-INDEX-DROP(c): snapshot of this zone's outstanding index-drop
     * gap, taken BEFORE the SMEMBERS this purge is about to launch, so the
     * reply can tell a full enumeration from one that raced a drop. Non-zero
     * => the index set may be short an entry that is still resident in L1 and
     * still serving, and the reply says "complete":false.
     *
     * Set on BOTH purge paths, from different counters:
     *   - auto-Vary (is_auto_vary): varidx_drops - varidx_reissues, i.e. the
     *     UNHEALED drops only, because that index self-heals on a later hit.
     *   - by-tag (admin.c ?tag=): tag_index_drops + tag_cap_drops. Neither
     *     fault class self-heals -- there is no tag_index_reissues counter
     *     and no cap-drop reissue path either (see shctx_t) -- so every
     *     drop of EITHER class this zone has ever taken stays outstanding.
     *
     * Zone-scoped, not base- or tag-scoped: the index set carries no
     * per-member pending flag to check directly. Deliberately conservative
     * in one direction -- it can call a purge degraded because some OTHER
     * base or tag in the zone has an outstanding drop, never the reverse. A
     * false "degraded" costs an operator a re-purge; a false "complete" is
     * the defect this exists to catch. */
    ngx_uint_t                         pending_at_launch;
} ngx_http_cache_turbo_tagpurge_t;

ngx_int_t ngx_http_cache_turbo_tag_purge_complete(ngx_http_request_t *r,
    void *data, ngx_str_t *members, ngx_uint_t nmembers,
    const ngx_http_cache_turbo_redis_walk_t *walk);

/* Fire one background subrequest for `uri` (+ optional `args`) so the origin is
 * hit and the response stored (module.c; shared with the admin warm path).
 * `snap`/`snap_len` are an optional pinned copy of the entry's current stored
 * blob (as used by the SWR background-refresh callers) -- when non-NULL, its
 * ETag / Last-Modified (if any) are injected as If-None-Match /
 * If-Modified-Since on the subrequest so a stale-while-revalidate refresh can
 * be answered 304 by the origin instead of always paying a full body. Pass
 * NULL/0 (the admin warm path) for the old unconditional-GET behaviour.
 *
 * `unparsed_uri_src`: the operator-supplied uri text in its ORIGINAL
 * (still percent-escaped) form, as it appeared on the wire/in the warm list --
 * NOT `uri`, which by this point may already be percent-decoded. When `uri`/
 * `args` are not byte-identical to r->uri/r->args (the admin warm path; see
 * UB-PROXYNULLURI in module.c), warm_one() cannot inherit r->valid_unparsed_uri
 * and needs its own escaped request-target text to synthesise a private
 * sr->unparsed_uri so ngx_http_proxy_create_request() never falls into the
 * memcpy(dst, NULL, 0) UB at ngx_http_proxy_module.c:1383. Pass NULL when the
 * caller has no such raw text (internal warms always pass byte-identical
 * uri/args and take the inherit path instead). */
ngx_int_t ngx_http_cache_turbo_warm_one(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args, u_char *snap, size_t snap_len,
    ngx_http_cache_turbo_ctx_t **ctx_out, ngx_str_t *unparsed_uri_src);


/* ---- admin.c (admin request handler) ---- */
ngx_int_t ngx_http_cache_turbo_admin_handler(ngx_http_request_t *r);


#endif /* NGX_HTTP_CACHE_TURBO_MODULE_H_INCLUDED_ */
