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


/*
 * One cached object living in the shared-memory slab. The node key is the
 * 32-byte hash of the cache key; the variable-length body (headers + payload,
 * serialised) is slab-allocated separately and pointed to by data/len.
 */
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

typedef struct {
    ngx_rbtree_node_t        node;       /* node.key = crc32 of cache key  */
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


typedef struct {
    ngx_http_cache_turbo_shctx_t  *sh;
    ngx_slab_pool_t               *shpool;

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
} ngx_http_cache_turbo_zone_t;


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

    /* Vary-aware suffix (v3-4). Bitmask of NGX_HTTP_CACHE_TURBO_VARY_* selecting
     * which buckets are appended to $cache_turbo_normalized_args so responses
     * that legitimately differ by encoding (br/gzip/identity) or device
     * (mobile/desktop) get separate cache slots. NGX_CONF_UNSET / 0 = off, so
     * v3-1 keys are unchanged unless cache_turbo_normalize_vary opts in. */
    ngx_int_t                normalize_vary;

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
    unsigned                 captured:1;  /* response captured for store    */
    unsigned                 served:1;    /* we served from cache           */
    unsigned                 stale_hit:1; /* served stale (for X-Cache)      */
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
    /* auto-Vary PURGE generation (COR-5). Resolved from the L1 marker by
     * vary_resolve and reused at store so the variant key + marker agree. Stays
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
     * void * because ngx_http_cache_turbo_blob_cln_t is private to module.c,
     * which is the only file that dereferences this. */
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
 *   6  u16 flags     (reserved)  24  i64 created       40  u32 sie_ttl
 *   8  u32 status    12 u32 nheaders                   44  = header size
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
} ngx_http_cache_turbo_blob_hdr_t;

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


extern ngx_module_t  ngx_http_cache_turbo_module;


/* ---- shm.c ---- */
ngx_int_t ngx_http_cache_turbo_shm_init_zone(ngx_shm_zone_t *zone, void *data);

/* PERF-7 zero-copy serve refcount. acquire() pins a blob for an in-flight serve
 * and MUST be called with shpool->mutex held (same critical section as the
 * lookup that produced `data`). release() is the request-pool cleanup: it takes
 * the mutex itself, drops the ref, and frees the slab if the owning node has
 * already detached it. `data` is ngx_http_cache_turbo_node_t.data (the blob ptr,
 * never NULL). */
void ngx_http_cache_turbo_blob_acquire(u_char *data);
void ngx_http_cache_turbo_blob_release(ngx_http_cache_turbo_zone_t *z,
    u_char *data);

ngx_http_cache_turbo_node_t *
    ngx_http_cache_turbo_shm_lookup(ngx_http_cache_turbo_zone_t *z,
        u_char *key_hash, uint32_t hash);

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
    ngx_http_cache_turbo_node_t *ctn, time_t now, ngx_uint_t protected_pct);

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

/* PERF-1/2: drop many L2 keys in ONE connection. Pipelines chunked variadic
 * UNLINK commands (each UNLINK deletes up to a fixed cap of keys and returns a
 * single integer reply) instead of one fire-and-forget connection per key, so a
 * large tag/all purge can no longer open thousands of sockets at once. Key
 * bytes are copied into the op pool, so the caller's array need not outlive the
 * call. No-op when L2 is disabled or nkeys == 0. */
void ngx_http_cache_turbo_redis_del_many(ngx_http_cache_turbo_loc_conf_t *clcf,
    ngx_str_t *keys, ngx_uint_t nkeys);

/* Build the tag-set key "<prefix>tag:<name>" into buf (must hold
 * prefix.len + sizeof("tag:")-1 + name_len). Returns bytes written. */
size_t ngx_http_cache_turbo_redis_tagkey(ngx_str_t *prefix, u_char *name,
    size_t name_len, u_char *buf);

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

/* Sync-park SMEMBERS "<prefix>tag:<name>": parks the request (count++) and,
 * when the array reply lands, invokes cb(r, data, members, n) then finalizes
 * with the rc cb returned. Returns:
 *   NGX_DONE  - parked; caller must return NGX_DONE
 *   NGX_ERROR - could not start (L2 disabled or connect failed); caller
 *               produces its own response. */
ngx_int_t ngx_http_cache_turbo_redis_smembers(ngx_http_request_t *r,
    ngx_http_cache_turbo_loc_conf_t *clcf, u_char *name, size_t name_len,
    ngx_http_cache_turbo_redis_members_pt cb, void *data);

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
        uint32_t hash, ngx_int_t min_uses);

    /* S231-PERF-MISSLOCKS: merged count_miss()+claim() -- see
     * ngx_http_cache_turbo_shm_resolve_miss()'s comment for the exact
     * contract. Only called when min_uses > 1 AND cache_turbo_lock is on
     * (the case where count_miss() and claim() would otherwise run
     * back-to-back under two separate mutex holds on the same request pass). */
    ngx_int_t  (*resolve_miss)(ngx_http_cache_turbo_zone_t *z,
        u_char *key_hash, uint32_t hash, ngx_int_t min_uses, time_t lock_ttl,
        uint64_t *owner, ngx_int_t *count_miss_rc,
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
};

#define NGX_HTTP_CACHE_TURBO_CLAIM_WINNER  0
#define NGX_HTTP_CACHE_TURBO_CLAIM_LOSER   1
#define NGX_HTTP_CACHE_TURBO_CLAIM_FRESH   2

/* store_if() predicates (AUD-L2-PROMOTE-RACE / AUD-5XX-CTA) -- see the L1
 * vtable `store_if` comment for the exact refusal rule each one applies. */
#define NGX_HTTP_CACHE_TURBO_STORE_IF_NEWER            0
#define NGX_HTTP_CACHE_TURBO_STORE_IF_ABSENT_OR_DEAD   1

/* Cold-miss wait-loop poll interval (ms): a loser re-checks L1/L2 this often
 * until the winner fills the entry or cache_turbo_lock_timeout elapses (v10). */
#define NGX_HTTP_CACHE_TURBO_LOCK_POLL_MS  100

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
    void       (*tag_add)(ngx_http_cache_turbo_loc_conf_t *clcf,
        u_char *key_hash, u_char *name, size_t name_len, time_t ttl);
    /* L9: batched tag_add (one op for N tags). NULL on a backend without tag
     * support, exactly like tag_add -- callers must check it before use. */
    void       (*tag_add_many)(ngx_http_cache_turbo_loc_conf_t *clcf,
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

extern ngx_cache_turbo_backend_t  ngx_http_cache_turbo_redis_backend;
extern ngx_cache_turbo_backend_t  ngx_http_cache_turbo_memcached_backend;


#endif /* NGX_HTTP_CACHE_TURBO_MODULE_H_INCLUDED_ */
