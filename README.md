# nginx-cache-turbo-module

[![Build & Test](https://github.com/myguard-labs/nginx-cache-turbo-module/actions/workflows/build-test.yml/badge.svg)](https://github.com/myguard-labs/nginx-cache-turbo-module/actions/workflows/build-test.yml)
[![Security scanners](https://github.com/myguard-labs/nginx-cache-turbo-module/actions/workflows/security-scanners.yml/badge.svg)](https://github.com/myguard-labs/nginx-cache-turbo-module/actions/workflows/security-scanners.yml)
[![Fuzzing](https://github.com/myguard-labs/nginx-cache-turbo-module/actions/workflows/fuzzing.yml/badge.svg)](https://github.com/myguard-labs/nginx-cache-turbo-module/actions/workflows/fuzzing.yml)
[![Valgrind](https://github.com/myguard-labs/nginx-cache-turbo-module/actions/workflows/valgrind.yml/badge.svg)](https://github.com/myguard-labs/nginx-cache-turbo-module/actions/workflows/valgrind.yml)
[![CodeQL](https://github.com/myguard-labs/nginx-cache-turbo-module/actions/workflows/codeql.yml/badge.svg)](https://github.com/myguard-labs/nginx-cache-turbo-module/actions/workflows/codeql.yml)
[![ASan](https://github.com/myguard-labs/nginx-cache-turbo-module/actions/workflows/asan.yml/badge.svg)](https://github.com/myguard-labs/nginx-cache-turbo-module/actions/workflows/asan.yml)
[![CI Deep](https://github.com/myguard-labs/nginx-cache-turbo-module/actions/workflows/ci-deep.yml/badge.svg)](https://github.com/myguard-labs/nginx-cache-turbo-module/actions/workflows/ci-deep.yml)

A built-in page cache for nginx. Think of it as a tiny Varnish that lives
**inside** nginx — no extra daemon, no second port, no Lua.

> **Writeup:** [nginx-cache-turbo — a built-in page cache](https://deb.myguard.nl/articles/nginx-cache-turbo/).
> Ships in the **deb.myguard.nl nginx/angie stack** as
> `libnginx-mod-http-cache-turbo` (nginx) / `angie-module-http-cache-turbo`
> (Angie) — see [Building & the stack](#building--the-stack).

## Contents

- [The idea in 30 seconds](#the-idea-in-30-seconds)
- [The tiers: L0 → L1 → L2](#the-tiers-l0--l1--l2)
- [Mixing with nginx's native cache (`proxy_cache`)](#mixing-with-nginxs-native-cache-proxy_cache)
  - [When to pick which](#when-to-pick-which)
- [Quick start](#quick-start)
- [What it will and won't cache](#what-it-will-and-wont-cache)
  - [Letting the origin decide (`cache_turbo_require_header`)](#letting-the-origin-decide-cache_turbo_require_header)
  - [Conditional requests (`304 Not Modified`)](#conditional-requests-304-not-modified)
  - [Auto-Vary (read the response `Vary`)](#auto-vary-read-the-response-vary)
- [CMS backends (`cache_turbo_backend`)](#cms-backends-cache_turbo_backend)
  - [What each preset skips](#what-each-preset-skips)
  - [Interactions and safety](#interactions-and-safety)
- [The cache key](#the-cache-key)
  - [Cache-key normalization](#cache-key-normalization)
- [Presets (pick a vibe, skip the knobs)](#presets-pick-a-vibe-skip-the-knobs)
- [Microcaching (1-second TTL for APIs and PHP-FPM)](#microcaching-1-second-ttl-for-apis-and-php-fpm)
- [Long-tail URLs: reach for `cache_turbo_min_uses` first](#long-tail-urls-reach-for-cache_turbo_min_uses-first)
- [Scan-resistant eviction: `cache_turbo_scan_resistant`](#scan-resistant-eviction-cache_turbo_scan_resistant)
- [Zone sizing under LRU pressure](#zone-sizing-under-lru-pressure)
- [What autotune actually tunes](#what-autotune-actually-tunes)
- [Full example (the works)](#full-example-the-works)
  - [Using the control panel](#using-the-control-panel)
- [Every directive in one place (full syntax)](#every-directive-in-one-place-full-syntax)
  - [Mutually exclusive / interacting directives](#mutually-exclusive--interacting-directives)
- [Directive synopsis](#directive-synopsis)
  - [Variables](#variables)
  - [Admin endpoint verbs](#admin-endpoint-verbs)
- [Monitoring (Prometheus + Grafana)](#monitoring-prometheus--grafana)
- [Redis L2 (shared cache)](#redis-l2-shared-cache)
  - [memcached L2 (alternative backend)](#memcached-l2-alternative-backend)
- [Building & the stack](#building--the-stack)
- [Benchmarking](#benchmarking)
- [License](#license)

## The idea in 30 seconds

Your backend (PHP, Node, whatever) is slow. The same pages get requested over
and over. So: the first time someone asks for `/blog/post-42`, nginx fetches it
from the backend **once**, keeps a copy in shared memory, and serves that copy
to everyone else. Backend barely gets touched.

The clever part is what happens when a copy gets **old**:

- **fresh** (young copy) → serve it instantly, backend never woken.
- **stale** (past its TTL but not ancient) → still serve the old copy
  *immediately*, and **one** request in the background goes and gets a new one.
  Nobody waits, and your backend doesn't get hammered by a thundering herd.
- **expired** (too old) → treat as a miss, fetch fresh.

That "serve old now, quietly refresh one copy" trick is called
**stale-while-revalidate (SWR)**. It's the whole point.

And when that background refresh **fails** — the origin returns a 5xx or times
out — cache-turbo keeps the good copy and serves it instead of surfacing the
error (**stale-if-error**), automatically, no config. An origin
`Cache-Control: stale-if-error=N` extends that grace past the normal stale
window (served as `X-Cache: STALE-IF-ERROR`). The one thing it can't do is
shield a page it never cached, so warm critical URLs ahead of an outage.

Optional extras: a shared **Redis** tier so a cluster of nginx boxes share one
cache, tag-based purging, cache warming, and live auto-tuning.

## The tiers: L0 → L1 → L2

cache-turbo is layered, fastest first. A request walks down only until something
answers:

```
            ┌────────────────────────── one nginx box ──────────────────────────┐
  client →  │  L1: shared-memory page cache  ──miss──▶  L2: Redis (optional)     │  ──miss──▶  origin
            │     (RAM, sub-millisecond)                  (shared by the fleet)   │            (your backend)
            └────────────────────────────────────────────────────────────────────┘
```

- **L1 — shared memory (always on).** The `cache_turbo_zone`. A hit here is
  RAM-speed and never leaves the worker. This is where SWR / single-flight /
  LRU eviction live. Per-box.
- **L2 — Redis (optional, `cache_turbo_redis`).** A tier *shared by every nginx
  box*. Touched only on an L1 **miss** (one `GET`) and on store (async
  write-through) — never on an L1 hit. So one box warming a page warms the whole
  fleet, and a restarted box refills from Redis instead of stampeding the origin.
- **origin — your backend.** Reached only when both L1 and L2 miss. SWR + the
  single-flight lock (and the cross-node Redis lock) keep origin hits to roughly
  one per stale cycle even under a stampede.

> Where's "L0"? When you put cache-turbo *in front of* nginx's own
> `proxy_cache` (next section), cache-turbo becomes the L0 in front of that
> on-disk L1 — see below.

## Mixing with nginx's native cache (`proxy_cache`)

You can run cache-turbo together with `proxy_cache` / `fastcgi_cache` — they sit
at **different layers**, so they stack cleanly:

```
                cache-turbo (ACCESS phase, shm)         proxy_cache (content phase, disk)
  request ─▶  ┌──────────────────────────────┐
              │  L1 lookup                    │
              │   ├─ HIT/STALE → serve, DONE ─┼──▶  (proxy_cache never runs)
              │   └─ MISS ────────────────────┼──▶  proxy_pass + proxy_cache ─▶ origin
              └──────────────────────────────┘            │
                          ▲                                │
                          └──── captures the response ◀────┘  (stores it in shm)
```

On a cache-turbo **hit** the request is finalized in the ACCESS phase and never
reaches `proxy_pass`, so `proxy_cache` is skipped entirely. On a **miss** the
request flows through `proxy_cache` as usual, and cache-turbo just captures
whatever comes back (disk-hit or origin) into its shm. So cache-turbo is an L0
in front of proxy_cache's disk L1.

Two sane patterns:

```nginx
# A) split by content — shm for hot HTML, disk for big media
location / {
    cache_turbo       ct;          # shm front
    cache_turbo_valid 60s;
    proxy_pass        http://app;
}
location /media/ {
    cache_turbo off;               # let the native disk cache handle bulk
    proxy_cache disk;
    proxy_pass  http://app;
}
```

```nginx
# B) stack both on the same location — shm L0 over a big disk L1
location / {
    cache_turbo       ct;
    cache_turbo_valid 30s;
    proxy_cache       disk;        # survives reloads, holds more than RAM
    proxy_cache_valid 200 10m;
    proxy_pass        http://app;
}
```

**Things to know when stacking:**

- **Independent storage + purge.** Same page may live in shm *and* on disk;
  purging cache-turbo does not purge `proxy_cache` (and vice-versa). Keep the
  disk TTL ≥ the shm TTL so the layers don't fight.
- **No header clash.** cache-turbo strips the native cache's `Age`,
  `X-Cache` and `X-Cache-Status` before storing, so an L1 hit never replays a
  frozen age/status. cache-turbo's own `X-Cache: HIT/STALE` is the source of
  truth; read `proxy_cache`'s state via `$upstream_cache_status` if you want it.
- **Layered staleness.** A cache-turbo SWR refresh goes through `proxy_cache`,
  which may serve *its* stale. If that matters, keep `proxy_cache` TTL ≤
  cache-turbo's, or disable proxy stale (`proxy_cache_use_stale off`).
- **Rule of thumb:** don't double-cache the *same* content. Use cache-turbo for
  what benefits from shm speed + SWR + Redis L2 + tag purge; use `proxy_cache`
  for a huge on-disk corpus that won't fit in RAM.

### When to pick which

`proxy_cache` is a fine, battle-tested cache. An honest side-by-side:

| | **cache-turbo** | **nginx `proxy_cache`** |
|---|:---:|:---:|
| **Store / phase** | shared memory, ACCESS phase | disk, content phase |
| **Throughput** | **+23–37 %** small/medium ([bench](BENCHMARK.md)) | baseline |
| **Stale-while-revalidate + stale-if-error** | on by default | manual (`proxy_cache_use_stale`) |
| **Dogpile / single-flight** | per-box **and** cross-fleet (Redis lock) | per-box (`proxy_cache_lock`) |
| **Shared / distributed cache** | Redis/memcached L2 across the fleet | per-box disk, every node cold alone |
| **One config for php-fpm *and* APIs** | same directives (`fastcgi_pass` + `proxy_pass`) | separate `fastcgi_cache` / `proxy_cache` |
| **Tag purge · auto-Vary · CMS auto-classify · Prometheus** | built in | none |
| **Survives reload / restart** | no — shm cleared (Redis L2 softens) | yes, persists on disk |
| **Capacity** | bounded by RAM | huge on-disk corpus |
| **Built into nginx** | no — dynamic module | yes, nothing to install |
| **Maturity** | newer | a decade of edge cases |

> **Pick:** hot HTML and dynamic apps → **cache-turbo**. A giant cold / long-tail
> on-disk archive → **`proxy_cache`**. In doubt, **stack them** — cache-turbo as
> the RAM L0 over a `proxy_cache` disk tier ([above](#mixing-with-nginxs-native-cache-proxy_cache)).
>
> **Not** a differentiator: *caching* dynamic / php-fpm / API responses —
> `fastcgi_cache` / `proxy_cache` do that too. cache-turbo's edge is the unified
> config plus the single-flight + SWR that make aggressive 1-second microcaching
> genuinely safe (the backend sees ~one request per second per key, not a
> stampede).

## Behind a CDN / multi-tier caching

When cache-turbo runs as a **shared cache behind a CDN** (Cloudflare, Fastly,
Akamai …), the origin often needs *three* different TTLs: one for the browser,
one for the CDN edge, and one for this shared cache. Plain `Cache-Control` can
only carry two (`max-age` for private caches, `s-maxage` for shared). RFC 9213
adds **targeted** cache-control headers for exactly this, and with
`cache_turbo_cache_control honor` cache-turbo reads them at a **higher priority
than `Cache-Control`**:

| Priority | Header | Emitted by | TTL token |
|:---:|---|---|---|
| 1 (highest) | `Surrogate-Control` | Fastly, Akamai | `max-age` |
| 2 | `CDN-Cache-Control` | Cloudflare (RFC 9213) | `s-maxage` > `max-age` |
| 3 | `Cache-Control` | everyone | `s-maxage` > `max-age` |
| 4 (lowest) | `Expires` | legacy | absolute date |

So an origin can say:

```http
Cache-Control: max-age=60          # browser: 60s
CDN-Cache-Control: max-age=600     # this shared cache (and the CDN): 10 min
Surrogate-Control: max-age=3600    # Fastly edge specifically: 1 h
```

and cache-turbo stores it for **1 hour** (the `Surrogate-Control` value),
ignoring the 60s browser TTL. Semantics:

- **TTL precedence** — the highest-priority present header wins (table above).
  Only active under `cache_turbo_cache_control honor`.
- **`no-store` veto** — a targeted `no-store`/`private`/`max-age=0` refuses the
  shared store the same way a plain `Cache-Control: no-store` does. An origin can
  therefore keep a page out of *this* cache while still letting the browser cache
  it.
- **Stripped before store** — both targeted headers are removed before the entry
  is stored (like `Age`), so a cached **HIT never replays them downstream** to
  the browser or a next cache tier — you (the shared cache) are their intended
  consumer.
- **`ignore` mode** — `cache_turbo_cache_control ignore` discards the targeted
  variants too, alongside `Cache-Control`.

> **See also:** [`cache_turbo_cache_control`](#directive-synopsis) for the full honor/
> respect/ignore semantics, and [Mixing with nginx's native
> cache](#mixing-with-nginxs-native-cache-proxy_cache) for stacking with
> `proxy_cache`.

## Quick start

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    # one shared-memory zone, 256 MB, named "ct"
    cache_turbo_zone name=ct 256m;

    server {
        listen 80;

        location / {
            cache_turbo       ct;        # turn caching on, use zone "ct"
            cache_turbo_valid 10s;       # a copy is "fresh" for 10s
            proxy_pass http://127.0.0.1:8080;   # your slow backend
        }
    }
}
```

That's the whole config. With just `cache_turbo ct;` the default key is already
`$host$uri$cache_turbo_normalized_args`, so vhosts don't collide and tracking
params (`utm_*`, `fbclid`, …, plus `sid`, `sessionid`, `tmp_*`) are stripped and
args are order-insensitive out of the box — no extra directives needed. Want it
spelled out, or to tweak it?

```nginx
location / {
    cache_turbo                 ct;
    cache_turbo_key             $host$uri$cache_turbo_normalized_args;  # = the default
    cache_turbo_normalize_strip sid sessionid "tmp_*";                  # already built in
    proxy_pass http://127.0.0.1:8080;
}
```

Curl it twice and look at the `X-Cache` header:

```console
$ curl -s -o /dev/null -D- localhost/ | grep -i x-cache   # 1st time: nothing (a miss)
$ curl -s -o /dev/null -D- localhost/ | grep -i x-cache
X-Cache: HIT                                              # 2nd time: served from RAM
```

> Use **GET** (`-s -o /dev/null -D-`), not `curl -sI`. A `HEAD` response is never
> stored, so `-I` can never show you a `HIT` no matter how many times you run it.

`X-Cache: HIT` = fresh from cache. `X-Cache: STALE` = old copy while a refresh
runs. No header = it went to the backend (a miss).

## What it will and won't cache

By default it stores a `200 OK` to a `GET` (never a `HEAD` — that would store an
empty body). You can also cache **redirects and negative responses** by giving
their status codes a TTL:

```nginx
cache_turbo_valid 30s;              # the default / 200 TTL
cache_turbo_valid 301 302 308 1h;   # cache redirects
cache_turbo_valid 404 410 1m;       # negative caching
cache_turbo_valid 0;                # "cache forever" (stays fresh, never expires)
```

A `TIME` of `0` means **cache forever**: the copy stays *fresh* indefinitely (it
is never served stale and never re-fetched on its own — purge it explicitly to
update). Internally this is a long finite TTL, so it still works across the L2
(Redis/memcached) tier like any other entry.

> `cache_turbo_valid` **replaces, it does not merge.** If a nested `location`
> sets any `cache_turbo_valid` of its own, it discards the *entire* set inherited
> from the parent (all status-code TTLs included) — standard nginx array-merge
> semantics. Re-state every status line you still want in the nested block; don't
> assume the parent's `301`/`404` TTLs carry through once you add a child rule.

And it **refuses** to cache anything that looks per-user, so you don't
accidentally serve Alice's logged-in page to Bob:

- request had an `Authorization` header → not cached **and not served from cache**
  (an anonymously-primed copy is never handed to a credentialed request)
- response sets a cookie (`Set-Cookie`) → not cached
- response says `Cache-Control: private | no-store | no-cache | max-age=0 |
  s-maxage=0` → not cached
- `206 Partial Content` → never cached (the cache key has no `Range`, so a stored
  partial could be served for a different/whole range)
- a response that arrives **already compressed from the origin** (a non-identity
  `Content-Encoding` set *before* our header filter, i.e. the upstream itself
  compressed it) → not cached. The module caches the **identity** body and lets
  the local gzip/zstd/brotli filter re-encode per client; it holds no identity
  copy of an origin-pre-compressed body, so replaying it encoding-blind would
  break clients that negotiated a different coding. (Locally-compressed responses
  are fine — our body filter runs *above* the compressors and captures identity.)

Hop-by-hop / framing headers (`Connection`, `Transfer-Encoding`,
`Content-Length`, `Content-Encoding`, `Set-Cookie`, `Date`, `Server`, …) are
stripped before storing and rebuilt on the way out, so a cached response is
still well-formed.

The `Date` is re-emitted as a **stable** timestamp for the cached
representation (it does not advance on every hit), and an `Age` header reports
how long the copy has been cached — the two stay mutually consistent (RFC 9111).

It also honours a few **request** `Cache-Control` directives: `no-cache` /
`max-age=0` (and `Pragma: no-cache`) force a revalidation against the origin
(a force-refresh); `no-store` runs the request to the origin and does **not**
store the response; and `only-if-cached` answers `504 Gateway Timeout` when the
page is in neither L1 nor L2, instead of contacting the origin.

### Letting the origin decide (`cache_turbo_require_header`)

Everything above is the module deciding from the HTTP it can see. Some origins
answer things HTTP cannot separate: a **GraphQL** endpoint serves a read query
and a write mutation on the *same* URI and method, and reports errors as
`200 OK` with an `errors` member in the body. Nothing at the HTTP level tells
those apart, and the module deliberately never parses the body (it stays an
opaque blob), so only the application can say.

`cache_turbo_require_header` inverts the default on a location — from *cacheable
unless something vetoes it* to **uncacheable unless the origin affirms it**:

```nginx
location /graphql {
    cache_turbo                main;
    cache_turbo_require_header X-GraphQL-Cacheable;   # a header NAME
    proxy_pass http://app;
}
```

The response is stored only if it carries that header with an **affirmative**
value — `yes`, `1`, or `on`, case-insensitive, matched whole. Everything else
refuses the store: header absent, `no`, a value like `note`, or the same header
sent twice with conflicting values (ambiguous, so the only safe reading is
"don't"). It **fails closed** by construction — any doubt is a cache miss,
never a wrong serve. (An *empty* value reads as absent: nginx does not forward
an empty-valued header from the upstream, so it never reaches the gate — either
way, no store.)

Two details worth knowing:

- The argument is a plain header **name**, not a `$variable`. The value is read
  from the *response*; a variable here would be evaluated against the *request*
  and quietly gate on the wrong thing, so the name is validated at config time.
- The header is **stripped before storing** (like `Age` and the RFC 9213
  targeted directives): this cache is its intended consumer, and a hit must not
  replay the origin's internal signal downstream.

Unset — the default, and every location that doesn't name it — leaves the normal
rules above completely untouched.

### Conditional requests (`304 Not Modified`)

If the origin gave the cached `200` an `ETag` or `Last-Modified`, the module
answers conditional requests straight from cache — no body, no origin round
trip. A `GET`/`HEAD` carrying `If-None-Match` (matched with the weak comparator,
`*` matches any cached entry) or `If-Modified-Since` gets a `304 Not Modified`
when the client's copy is still current; `If-None-Match` wins when both are
present (RFC 7232). Anything else serves the full cached body. This is automatic
— there is no directive to set.

A `304` is only answered from a **fresh** entry. A stale entry (being served
while a refresh runs) has not been revalidated against the origin, so it serves
the full body rather than asserting "still current" with a `304` (RFC 9111).

### Auto-Vary (read the response `Vary`)

Turn on `cache_turbo_auto_vary on` and the module reads the response's own
`Vary` header and splits the cache by the named **request** header automatically
— no need to pre-declare the axes. It honours a safe whitelist:
`Accept-Encoding` (bucketed br/gzip/identity/zstd), `User-Agent` (mobile/desktop
class), `Accept-Language` (primary-subtag class) and `Origin` (raw value,
unfolded: it's a CORS security boundary, collapsing distinct origins into one
class would let one origin's response serve another's CORS headers). A response
with `Vary: *`, or one that varies on `Cookie` or `Authorization`, is treated as
**uncacheable** (those vary per-user — caching them would poison or leak across
users). **Any other named header is also treated as uncacheable** — the module
can't key on it, and caching a single representation for every value of that
header would serve the wrong one (RFC 9110 §12.5.5).

`Accept-Language` is folded to its **primary subtag only**, lowercased: the
first language-range of the header, cut at the first `-` (and any `;q=`
parameter dropped), capped at 8 bytes. `en-US,en;q=0.9` and `en-GB,en;q=0.8`
both fold to `en` and share a cache entry — the raw header would otherwise
spawn a distinct variant per browser locale string, blowing up the keyspace on
an i18n site with no benefit (nobody serves different bytes for `en-US` vs.
`en-GB`). An absent, empty, or malformed header folds to its own empty class
`""` rather than being skipped — skipping would collide the axis with a
genuinely present-but-empty header. Accepted cost: `pt-BR`/`pt-PT` and
`zh-Hans`/`zh-Hant` now share an entry; a site that truly serves different
content per region/script should use an explicit `cache_turbo_vary` for that
axis rather than relying on auto-Vary.

> Don't double-partition the same axis. If you both turn on
> `cache_turbo_auto_vary` *and* add the matching `cache_turbo_normalize_vary`
> bucket (e.g. `encoding`) for an axis the origin already lists in `Vary`, the
> cache splits on it **twice** — once via the normalized-args key, once via the
> variant key — multiplying the slot count for no benefit. Pick one mechanism per
> axis: `normalize_vary` when you know the axis up front, `auto_vary` to learn it
> from the response.

Keying is two-level and node-local: the first time a URL's response is seen to
vary, the module records a tiny *vary marker* in L1 and stores the body under a
secondary *variant* key; later requests read the marker and resolve straight to
their variant. The base slot stays empty for varied URLs, so a node that hasn't
learned the `Vary` yet simply misses to origin — it never serves the wrong
variant. Off by default.

> **`Vary: Accept-Encoding` is harmless but redundant here.** The module captures
> the **identity** (uncompressed) body — its body filter runs *above*
> gzip/zstd/brotli, which then re-encode per client on every MISS *and* HIT (the
> `proxy_cache` model). So one stored copy already serves every encoding
> correctly; an `Accept-Encoding` vary axis just stores up to four byte-identical
> copies (`zstd`/`br`/`gzip`/`identity`) of the same URL. It is **correct, only
> wasteful** — most origins set `Vary: Accept-Encoding` by default, so `auto_vary`
> will partition on it. Leave it; a future version may collapse the axis. (An
> origin that *pre-compresses* its own response is refused outright — see
> [What it will and won't cache](#what-it-will-and-wont-cache) — so encoding-keyed
> caching is never actually needed.)

> **If your origin emits `Vary`, turn `cache_turbo_auto_vary on`.** With
> auto-Vary **off** (the default) the cache keys on the **request**, not on the
> response's `Vary`, and there is **no safety net**: a `Vary:`-carrying response
> is stored under a Vary-blind key and the first variant stored is served to
> *every* client (gzip-vs-brotli, mobile-vs-desktop, language, …) — a
> cache-poisoning / wrong-representation hazard (RFC 9110 §12.5.5). So for any
> varied origin either enable `cache_turbo_auto_vary`, or fold the axis into the
> key yourself with `cache_turbo_normalize_vary` (below) or an explicit
> `cache_turbo_key`. (There is no `cache_turbo_vary_safe` refuse-to-store knob —
> `auto_vary` is the supported mechanism.)

## CMS backends (`cache_turbo_backend`)

A page cache in front of a CMS has one classic footgun: cache a *logged-in* page,
the admin dashboard, or a cart, and serve it to the world. `cache_turbo_backend`
is the built-in guard — name your CMS and the module **auto-skips** the dynamic
surfaces (login/session traffic, admin URIs, search/preview) straight to the
origin, **never capturing them**, so only anonymous, shareable pages land in the
cache.

```nginx
cache_turbo            ct;
cache_turbo_backend    wordpress;          # one or more: wordpress woocommerce joomla
                                           # xenforo discourse phpbb drupal mediawiki
                                           # magento ghost
```

**Every preset is opt-in — name the backends you actually run.** They **stack**,
and spaces and `|` are interchangeable separators:

```nginx
cache_turbo_backend wordpress woocommerce;      # the same thing,
cache_turbo_backend wordpress|woocommerce;      # spelled three ways
cache_turbo_backend wordpress | woocommerce;
```

`cache_turbo_backend none;` means **no preset here**. Its job is to switch off a
preset inherited from the `server` block for one `location` — without it, a
server-level `cache_turbo_backend wordpress;` applies everywhere below it and
there is no way to opt a single location out.

> **There is no `generic` / `auto` union, and both spellings are a config error.**
> They used to mean `wordpress` + `woocommerce` + `joomla`. That was never a safe
> default:
>
> - it **never covered every backend** — it named 3 of the 12 presets that now
>   exist, so `auto` on a Drupal site silently enabled *no* Drupal rules;
> - its **`woocommerce`** shipped without implying `wordpress`, leaving
>   `/wp-admin/` cacheable (see [woocommerce.md](docs/woocommerce.md));
> - the **`joomla` in it ships no cookie rule at all**, so `auto` on a Joomla site
>   *looked* like it protected logged-in users and did not.
>
> A default that is only correct if you already know which parts of it are wrong
> is a footgun with a friendly name. nginx now **refuses to start** and names the
> replacement — rather than accepting the word and enabling nothing, which on an
> existing WordPress config would quietly start caching `/wp-admin/`.

### What each preset skips

A request is sent to the origin uncached if it matches **any** of three checks
for an active preset: a **URI prefix**, the **presence of a query arg**, or a
**substring of the whole `Cookie` header** — a raw, undelimited search across
cookie names *and* values, not a lookup of a cookie name (the login/session
cookies carry per-session suffixes, so it matches as a substring). Because the
search is not anchored to a name, a cookie **value** can trip the rule as
readily as a name: a rule's literal must be distinctive enough that it cannot
plausibly appear as an arbitrary value.

| Preset | URI prefixes | Query args | Cookie header substrings |
|---|---|---|---|
| `wordpress`   | `/wp-admin/`, `/wp-login.php`, `/wp-cron.php`, `/xmlrpc.php`, `/wp-json/` | `preview`, `rest_route` | `wordpress_logged_in_`, `wp-postpass_`, `comment_author_` |
| `woocommerce` | `/cart`, `/checkout`, `/my-account` | `wc-ajax` | `woocommerce_items_in_cart`, `woocommerce_cart_hash`, `wp_woocommerce_session_` |
| `joomla`      | `/administrator/` | — | `joomla_remember_me_` ‡ |
| `xenforo` † ¤ ✦ | `/admin.php`, `/install/`, `/api/`, `/login`, `/logout`, `/lost-password`, `/register`, `/account`, `/conversations`, `/direct-messages`, `/misc` | `_xfToken` | `xf_session`, `xf_user`, `xf_session_admin`, `xf_lscxf_logged_in`; *(key)* `xf_style_id`, `xf_style_variation`, `xf_language_id` |
| `discourse` † | `/admin`, `/session`, `/auth/`, `/login`, `/logout`, `/signup`, `/my/`, `/message-bus/`, `/drafts`, `/presence/`, `/notifications`, `/user_actions` | `api_key`, `api_username` | `_t=` |
| `phpbb` †     | `/ucp.php`, `/mcp.php`, `/adm/`, `/posting.php`, `/memberlist.php`, `/search.php`, `/report.php` | `sid` | *(value)* `…_u != 1` ∆ |
| `drupal` †    | `/user`, `/admin`, `/node/add`, `/system/`, `/core/install.php`, `/jsonapi`, `/oauth` | — | `SESS` ¥ |
| `mediawiki` † | — ¶ | `veaction`, `returnto`, mutating `action=` values ‡ | `Token=`, `_session=`, `UserID=` |
| `magento` † ✦ | `/checkout`, `/customer`, `/graphql`, `/rest`, `/soap`, `/sales`, `/newsletter`, `/wishlist`, `/paypal`, `/review`, `/page_cache/block/esi`, `/health_check.php` | — | *(key)* `X-Magento-Vary` ✦ |
| `shopware6` † ✦ | `/account`, `/checkout`, `/admin`, `/api`, `/store-api` | — | *(key)* `sw-cache-hash` ✦ |
| `ghost` †     | `/ghost/`, `/members/`, `/p/`, `/r/` | `uuid`, `key`, `token`, `gift` | `ghost-members-ssr`, `ghost-admin-api-session` |
| `wagtail` † § | `/admin/`, `/django-admin/`, `/documents/` | — | `sessionid` |
| `kirby` † §   | `/panel` | — | `kirby_session` |
| `typo3` † ※   | `/typo3` | — | `fe_typo_user`, `be_typo_user` |
| `invision` †  | `/admin`, `/login`, `/register`, `/lostpassword`, `/messenger` | `do=compose`, `do=post`, `do=reply`, `do=report`, `module=messaging` | `_loggedIn` (suffix); *(key)* `ips4_hasJS`, `ips4_theme`, `ips4_language` |
| `smf` †       | — | `action=admin`, `action=login`, `action=login2`, `action=logintfa`, `action=logout`, `action=profile`, `action=pm`, `action=post`, `action=post2`, `action=moderate`, `action=reporttm`, `action=xmlhttp` | `SMFCookie` (presence-only) |
| `vanilla` †   | `/dashboard`, `/entry/`, `/messages/`, `/post/` ⁂ | — | `Vanilla=` (presence-only) |
| `punbb` †     | `/admin.php`, `/admin/`, `/login.php`, `/post.php`, `/message_send.php`, `/message_delete.php`, `/misc.php` | — | `forum_cookie`, `punbb_cookie` (presence-only) |
| `phorum` †    | `admin.php`, `login.php`, `register.php`, `pm.php`, `posting.php`, `post.php`, `moderation.php`, `control.php`, `ajax.php`, `report.php`, `follow.php` | — | `phorum_session_v5`, `phorum_session_st`, `phorum_admin_session_v5`; *(key)* `list_style` |
| `yabb` †      | — | `action=post`, `action=post2`, `action=login`, `action=login2`, `action=register`, `action=register2`, `action=admin`, `action=pm`, `action=imsend`, `action=imsend2` | `Y2User-`, `Y2Pass-`, `Y2Sess-` (prefix) |
| `mybb` †      | `/member.php`, `/usercp.php`, `/private.php`, `/modcp.php`, `/newthread.php`, `/newreply.php`, `/editpost.php`, `/polls.php`, `/admin/`, `/xmlhttp.php` | `action=login`, `action=do_login`, `action=logout`, `action=do_logout`, `action=register`, `action=do_register`, `action=activate`, `action=lostpw`, `action=do_lostpw`, `action=resetpassword` | `user` (suffix, presence); *(key)* `mybbtheme`, `mybblang` |
| `vbulletin` † | `/login.php`, `/register.php`, `/usercp.php`, `/private.php`, `/profile.php`, `/cron.php`, `/admincp/` | — | `userid`, `password` (suffix, non-empty), `imloggedin` == `yes`; *(key)* `bb_language` |

† **Opt-in, like every preset.** These backends' dynamic surfaces are generic
English paths (`/login`, `/register`, `/user`, `/admin`, `/session`) that an
unrelated site may legitimately serve as perfectly cacheable pages. Enabling one
you do not run punches holes in your own cache — which is why none of them is
ever enabled implicitly, and why the old `generic` union is gone. Name them:
`cache_turbo_backend xenforo;`.

⁂ **Vanilla ships no `/api` row**, and that is a known gap rather than a
decision: Vanilla's API v2 is Bearer-authenticated, so it is the same
header-auth class as `magento /rest` and `drupal /jsonapi`. It is absent
because `github.com/vanilla/vanilla` now 404s and the prefix cannot be
verified against any surviving upstream tree. Add `cache_turbo_bypass_uri
/api;` if you serve it.

‡ `edit`, `submit`, `delete`, `protect`, `unprotect`, `purge`, `rollback`,
`revert`, `watch`, `unwatch`, `markpatrolled`, `mcrundo`, `mcrrestore` — the
mutating half of `ActionFactory::CORE_ACTIONS`. The read half (`view`,
`history`, `raw`, `render`, `info`, `credits`) stays cacheable.

¶ **`mediawiki` deliberately ships NO URI rule**, and that is the correct shape —
it is what upstream does. It used to bypass `/index.php`, `/load.php` and
`/api.php`; all three were wrong. On a stock wiki `$wgArticlePath` is
`/index.php?title=Foo`, so **`/index.php` is the article read path** — that rule
bypassed essentially every article read. `/load.php` (ResourceLoader) and
`/api.php` are among the hottest *cacheable* objects on a wiki; Wikimedia's
production VCL explicitly ring-fences them, by ticket number (T102898, T113007),
against a rule that would have made them private. Their frontend has no
path-based pass rule at all. The cookie rules plus the Cache-Control floor are
the whole mechanism. Do not re-add a path rule here without a source that says
MediaWiki cannot cache it.

∆ **A cookie VALUE predicate, not a name match.** Most presets classify on cookie
*name* presence. That is useless for an app that issues the **same** cookie to
guests and members and puts the distinction in the **value** — a presence rule
there matches everyone and identifies nobody. phpBB is the case: every non-bot
visitor gets `<cookie_name>_u`, holding `1` (`ANONYMOUS`) for a guest and the
real `user_id` for a member ([`session.php`](https://github.com/phpbb/phpbb/blob/master/phpBB/phpbb/session.php),
[`constants.php`](https://github.com/phpbb/phpbb/blob/master/phpBB/includes/constants.php)).
So the preset tests `…_u != 1`.

The cookie **name is matched by suffix**, deliberately: the prefix is
`config('cookie_name')` (default `phpbb`, so the wire name is `phpbb_u`), an ACP
setting that installers randomise and that any admin running two boards on one
domain changes. A literal-name rule silently **stops firing** on such a board —
and a bypass rule that stops firing caches the member's page and serves it to
strangers. Suffix matching is prefix-agnostic; it can over-match an unrelated
cookie ending in `_u`, which costs a needless bypass and never leaks.

An **unreadable** cookie (no `=`, malformed) **fails closed to bypass**: a false
bypass costs one cache miss, a false hit costs somebody else's session.

‡ **The cookie rule is a PARTIAL guard — you must still add your own.** One
preset cannot fully identify a logged-in user:

| Preset | What it can and cannot see | What you must do |
|---|---|---|
| `joomla` | `joomla_remember_me_` is a real fixed prefix and is auth-only — but it exists **only** for users who ticked "Remember Me". A normally-logged-in frontend user carries only the session cookie, whose name is `md5($secret . $session_name)` — a per-install hash with **no** stable substring. That user is invisible to the matcher. | **Add your own `cache_turbo_bypass` *and* `cache_turbo_no_store`** on your install's session-cookie name if your site has frontend logins ([guide](docs/joomla.md)) — the bypass skips only the lookup, so on its own the logged-in page is still stored. Do not read the cookie rule as "handled". |
| `phpbb` | **Handled by a cookie VALUE predicate** (∆). `_u`/`_k`/`_sid` are set for **guests too** (an anonymous visitor gets `_u=1` — `ANONYMOUS`), so presence identifies nobody; a logged-in member carries `_u=<user_id>`, never `1`. The preset now tests the **value**, matching the cookie **name by suffix** because the prefix is `config('cookie_name')` (default `phpbb`, often renamed). | **Nothing extra.** A stock `cache_turbo_backend phpbb;` now bypasses logged-in members. (Before this, it did **not** — see [guide](docs/phpbb.md).) |

¤ **`xenforo` cannot be made both safe and fast on stock XenForo.** Stock XF2 has
**no login-only cookie**. `xf_user` is the *remember-me* cookie — `completeLogin()`
only mints it inside `if ($remember)`, and "Stay logged in" is **unticked by
default** — so an ordinary member who just types their password carries **only**
`xf_session`. The preset therefore bypasses on `xf_session` as well, which is the
only correct cookie-only option, and it costs hit rate: XF's session is *lazy*, so
a clean first-time guest still caches, but a guest who logs out, trips 2FA, or
hits a captcha acquires a session and is uncacheable from then on. If you run
LiteSpeed's XF2 plugin you get `xf_lscxf_logged_in`, a true login-only cookie (the
plugin exists to create the cookie XF lacks) — that is the fast path, and you can
then drop `xf_session` with your own config. See [docs/xenforo.md](docs/xenforo.md).

¥ **`drupal`'s `SESS` rule over-matches, deliberately.** `SESS` is a substring of
`PHPSESSID` and `JSESSIONID`, so a co-hosted PHP or Java app under the same server
block also bypasses. That is a **hit-rate loss on the other app, never a leak** —
and it is the accepted price of closing a real leak on the Drupal side: Drupal
opens a session for **anonymous** users whenever anything writes to `$_SESSION`
(a status message after a form submit, cart contents), so a logged-in user's
`SESS<hash>` cookie must be excluded or their page can be stored and served on.
Narrow it with your own `cache_turbo_bypass $cookie_SESS<your-hash>` — paired
with a `cache_turbo_no_store` on the same cookie, since a bypass only skips the
lookup and still stores — if the collision costs you. Note `NO_CACHE` is **not** matched: it is contrib (not core) and is set
for *logged-out* visitors by design, so it would cost hits and buy no safety.

✦ **A cookie VALUE folded into the cache KEY, not a bypass.** `magento` is the one
preset that neither bypasses nor merely tests a cookie's value as a pass/fail
predicate (∆, above) — it puts the cookie's **value** into the cache key itself,
via a distinct `key_cookies` tier. `X-Magento-Vary` is Magento's
`Context::getVaryString()` — a salted hash of the sorted tuple
`{customer_group, customer_logged_in, store, currency}`, present only when a
field differs from its default (`Framework/App/Http/Context.php`). Magento's own
Varnish VCL hashes this value into the cache key (`vcl_hash`) and never passes on
it; the built-in PHP Full Page Cache folds the same value into its cache id
(`Framework/App/PageCache/Identifier.php`). Two independent upstream
implementations agree it is a key component, not a gate.

Bypassing on it — what this preset did before — was wrong: a plain anonymous
visitor never gets the cookie at all, so bypass caught only *non-default*
contexts (a EUR guest, a switched store view) that hold zero private data, for
no safety benefit (the cart is fetched client-side, never in the cached HTML).
Presence-keying would be a real leak (it collapses every non-default context —
customer A, customer B, a EUR guest — into one shared bucket). Value-keying is
neither: each vary context gets its own entry, exactly like upstream.

Key-cookie name matching is **exact**, not by suffix like ∆ — the value goes
straight into the cache key, so a loose match would let an attacker pick their
own bucket with a cookie like `NOT-X-Magento-Vary`. The module parses the raw
`Cookie:` header itself (scanning **every** `Cookie:` header a client sends, not
just the first) because nginx's `$cookie_` variables cannot represent a
hyphenated name (`$cookie_X_Magento_Vary` silently never matches — no `-`→`_`
translation for cookie names, unlike `$http_*`). See [magento.md](docs/magento.md).

`shopware6` uses the same tier on `sw-cache-hash`, and `xenforo` uses it on the
presentation cookies `xf_style_id` / `xf_style_variation` (XF 2.3 light/dark) /
`xf_language_id` — the visitor's chosen style, dark-mode variation and language
each get their own *shared* cache entry rather than being dropped from the cache.
Unlike Magento's identity-derived vary string these are pure preference values,
so there is no private data at stake; the point is purely to stop a dark-theme or
second-language visitor from missing the cache. See [xenforo.md](docs/xenforo.md).

§ **Cookie rule is *conditional* — and fails safe.** Both of these ride a cookie the
app issues only once a session actually exists, which is exactly what makes them
shippable. That property is the *application's* to break:

| Preset | The cookie stops meaning "logged in" when… | Consequence |
|---|---|---|
| `wagtail` | the Django app writes the session for guests — an anonymous cart, a large guest flash message (`contrib.messages` overflows to the session), or `CSRF_USE_SESSIONS=True` | every guest gets `sessionid` → **bypassed** → hit rate 0 |
| `kirby` | a template calls `csrf()` (any contact/search/comment form) | guests on **that page** get `kirby_session` → that page stops caching |

In both cases the failure direction is a **needless bypass — lost hits, never a
leak.** That asymmetry is the entire reason they ship while `flarum` does not: an
ordinary Flarum login (remember-me unticked, the default) carries only the
guest-issued `flarum_session`, so the only available cookie rule would serve a
**cached anonymous page to a logged-in user**. Verify with
`curl -sI https://site/ | grep -i set-cookie` — a logged-out request must set no
cookie — and re-check after deploys. [wagtail](docs/wagtail.md) ·
[kirby](docs/kirby.md) · [why not Django/Laravel themselves](docs/frameworks.md).

※ **`typo3` is the same lazy-session shape — but the *only* preset here that
fails UNSAFE, not safe.** `FrontendUserAuthentication` sets `$dontSetCookie =
true` by default (`FrontendUserAuthentication.php:155`), so an anonymous
frontend visitor gets no `fe_typo_user` — good hit rate, same mechanism as
`wagtail`/`kirby`. The difference: the cookie **name** is read from
`$GLOBALS['TYPO3_CONF_VARS']['FE']['cookieName']`
(`FrontendUserAuthentication::getCookieName()`, `:167`), an admin-overridable
default, not a per-install hash. If a site sets it, the preset's `fe_typo_user`
substring **silently stops matching** — and because this is a *bypass* rule, a
lost match means a **logged-in page gets cached and served to strangers**, the
opposite of the wagtail/kirby failure direction. If you override
`FE/cookieName`, add `cache_turbo_bypass $cookie_<your_name>;` **and**
`cache_turbo_no_store $cookie_<your_name>;` yourself — the bypass alone skips
only the lookup and still stores the logged-in response. The
preset also matches `be_typo_user` (the backend session) independently — it
catches an editor previewing the frontend, who carries no `fe_typo_user` at
all. See [typo3.md](docs/typo3.md).

So a WordPress admin (`wordpress_logged_in_…` cookie), a `?preview=true` draft, a
`/wp-json/` API call, a WooCommerce cart cookie, a `/checkout` page, a logged-in
XenForo member (`xf_user`), a Discourse user (`_t`) or a MediaWiki editor
(`…UserID`) all bypass the cache automatically — no hand-written
`cache_turbo_bypass`/`no_store` rules.

> **Per-application guides**, each with a copy-paste vhost (page cache + Redis
> L2), the cookie/key decisions and the application-specific footguns:
> [**WordPress**](docs/wordpress.md) · [**WooCommerce**](docs/woocommerce.md) ·
> [**Joomla**](docs/joomla.md) · [**XenForo**](docs/xenforo.md) ·
> [**Discourse**](docs/discourse.md) · [**phpBB**](docs/phpbb.md) ·
> [**Drupal**](docs/drupal.md) · [**MediaWiki**](docs/mediawiki.md) ·
> [**Magento**](docs/magento.md) · [**Shopware 6**](docs/shopware6.md) ·
> [**Ghost**](docs/ghost.md) ·
> [**Wagtail**](docs/wagtail.md) · [**Kirby**](docs/kirby.md) ·
> [**TYPO3**](docs/typo3.md) —
> index at [`docs/`](docs/README.md). Running a framework rather than one of these
> apps (Django, Laravel, Rails)? [**frameworks.md**](docs/frameworks.md) explains
> why there is no preset for it and how to derive your own rule.
>
> Caveats you should not skip: **`joomla` and `phpbb` ship no cookie rule** and do
> not protect logged-in users until you add your own bypass **plus a matching
> `cache_turbo_no_store`** — a bypass skips only the lookup and still stores
> (phpBB needs a *value* test — its cookies are handed to guests too); **`woocommerce` implies
> `wordpress`** automatically (so `/wp-admin/` is covered without stacking); **`drupal` +
> `mediawiki` lean on the origin's own `Cache-Control: private`**, so don't set
> `cache_turbo_cache_control ignore` on those; **`woocommerce`'s `/cart`,
> `/checkout`, `/my-account` prefixes are English defaults that match nothing on
> a translated store** (WooCommerce creates the pages in the site locale), so add
> your own `cache_turbo_bypass_uri` there and rely on the stacked `wordpress`
> cookie rules; and **`typo3`'s cookie name is
> admin-overridable (`FE/cookieName`) — if you change it, add your own
> `cache_turbo_bypass` *and* `cache_turbo_no_store`, or logged-in pages get
> cached** (this one fails unsafe,
> not safe — see [typo3.md](docs/typo3.md)).

#### "Session" in a cookie name does not mean "logged in"

The single most common way to wreck a cache with these presets. XenForo's
`xf_session`, Discourse's `_forum_session`, phpBB's `_sid` and MediaWiki's
`<prefix>_session` are **all handed to anonymous visitors**. Bypassing on one
drops most of your traffic out of the cache for zero safety gain — a performance
bug wearing the costume of a safety measure. None of them is in the table above,
on purpose.

**Check whether a cookie is set for a logged-out visitor before you bypass on
it.** `curl -sI` your site with no cookies and look at what comes back in
`Set-Cookie`.

#### XenForo: which cookies bypass, and which belong in the key

Stock XenForo has **no login-only cookie** (`xf_user` is only the *remember-me*
cookie, and "Stay logged in" is off by default), so the ordinary member carries
only `xf_session`. That forces `xf_session` into the bypass list even though
guests get it too — the full reasoning is in
[docs/xenforo.md](docs/xenforo.md#read-this-first-stock-xenforo-has-no-login-only-cookie).
The preset:

| Cookie / arg | Treatment | Why |
|---|---|---|
| `xf_user`, `xf_session_admin`, `xf_session` | **bypass** | the three identity signals. `xf_session` is guest-issued but is the only cookie a non-remember-me login carries — omitting it is a real cross-user leak. |
| `xf_lscxf_logged_in` | **bypass** | LiteSpeed addon's true login-only cookie (present only if you run it). |
| `_xfToken` (query arg) | **bypass** | XF's per-session CSRF token on some GET links (logout, style switcher). |
| `xf_style_id`, `xf_style_variation`, `xf_language_id` | **value-keyed** | presentation variants — style, XF 2.3 light/dark, language. Folded into the cache key by the preset, so each value gets its own *shared* entry. |
| `xf_consent` | *ignored* | changes embed HTML but fragments the cache heavily; key it yourself only if you need it. |

The style/language cookies are **value-keyed by the preset itself** now (tier-3
key-cookies, same engine as `magento`/`shopware6`) — you do not add them to
`cache_turbo_key` by hand. So do **not** do this:

```nginx
# WRONG — a per-session key gives every visitor their own private copy.
# Hit rate collapses to ~0, and logged-in pages still get *stored*.
cache_turbo_key $host$uri$cookie_xf_session$cache_turbo_normalized_args;
```

Keying on the *session* cookie does not make a logged-in page safely shareable —
it mints one entry per visitor (nothing is ever reused) while still **storing**
authenticated HTML. Bypassing sends it to the origin and never captures it. Key
on the *variant*, bypass the *identity* — and the preset does both for you:

```nginx
cache_turbo_backend xenforo;   # bypasses identity, value-keys style/language
cache_turbo_key     $host$uri$cache_turbo_normalized_args;   # plain key is enough
```

This is the same split LiteSpeed's own XenForo plugin makes (bypass on
`xf_lscxf_logged_in`/`xf_user`/`xf_session_admin`, *vary* on `xf_style_id` +
`xf_language_id`); we add `xf_style_variation`, the 2.3 dark-mode cookie that
post-dates that addon's rules.

Three caveats worth checking against your install:

- **Custom cookie prefix.** The names assume XenForo's default
  `$config['cookie']['prefix'] = 'xf_'`. If you changed it, the preset won't
  match — add your own `cache_turbo_bypass $cookie_<prefix>session
  $cookie_<prefix>session_admin $cookie_<prefix>user;` **and the same list on
  `cache_turbo_no_store`** (the bypass skips only the lookup and still stores).
  All three: `session` is
  the only cookie an ordinary (non-remember-me) login carries, `session_admin`
  the admin session, `user` remember-me. Bypassing `user` alone leaves ordinary
  and admin logins cacheable — the leak this preset exists to prevent.
- **The REST API (`/api/`)** authenticates on the `XF-Api-Key` header, not a
  cookie — the preset bypasses it on the URI so one client's private response is
  never served to another. Bypass any non-standard API path too.
- **A board in a subdirectory** (`/forums/…`) shifts every URI prefix above. The
  preset matches on `r->uri` from the site root and its prefixes are anchored at
  byte 0, so `/forums/login` does not match `/login` and the board gets **zero**
  URI-rule coverage — the admin surface included. Scoping the `location` does
  not help (it routes requests, it does not rewrite `r->uri`): declare the mount
  with `cache_turbo_backend_prefix /forums/;` (see the vhost example in
  [`docs/xenforo.md`](docs/xenforo.md)).

### Interactions and safety

- **Implies `cache_turbo_cache_control honor`** (unless you set it explicitly).
  So if your CMS plugin already emits `Cache-Control: no-cache` on a page it
  knows is dynamic, that page self-excludes at store time too — belt and braces.
  Pin a fixed TTL instead with an explicit `cache_turbo_cache_control respect;`
  (e.g. for microcaching — see below).
- **It is a floor, not the only one.** Auto-skip sits *under* the manual
  `cache_turbo_bypass` / `cache_turbo_no_store` overrides, and the universal
  safety rules still apply on top of it regardless of preset: a response with
  `Set-Cookie`, or a request carrying `Authorization`, is never cached. The
  preset widens the net for CMS-specific surfaces those generic rules miss (an
  admin URL with no cookie yet, a search query), it doesn't replace them.
- **Not a security boundary for your own private routes.** The presets cover the
  well-known CMS surfaces above; a custom `/members/`-style area still needs its
  own `cache_turbo_bypass $cookie_yoursession;` **plus
  `cache_turbo_no_store $cookie_yoursession;`** — a bypass skips only the lookup,
  so without the `no_store` half the private page is still stored under the
  shared key (or a raw default key,
  `cache_turbo_key $scheme$host$request_uri;`, for origins that don't reliably
  mark per-user responses `private`).

## The cache key

A "key" is just the string that decides whether two requests are *the same
page*. Default key is `$host$uri$cache_turbo_normalized_args` (the Host + path +
normalized args — tracking params stripped, args sorted), so two vhosts sharing
a zone never collide and `?utm_*`/arg-reordering hit one slot.

Set your own with `cache_turbo_key` using any nginx variables:

```nginx
cache_turbo_key $scheme$host$uri$is_args$args;
```

### Cache-key normalization

`$cache_turbo_normalized_args` rebuilds the query string so equivalent requests
share one slot: it sorts args (`?b=2&a=1` == `?a=1&b=2`) and drops tracking
params (built-in denylist: `utm_*`, `fbclid`, `gclid`, `msclkid`, `mc_eid`,
`_ga`, `ref`, `sid`, `sessionid`, `tmp_*`). Add more with
`cache_turbo_normalize_strip`, or nuke them all with
`cache_turbo_normalize_strip *` (a bare `*` is a zero-length prefix that matches
every arg name).

> **Alias caveat.** Because the default key *strips* `sid`/`sessionid`/`ref` and
> *sorts* the rest, two distinct URLs that differ only in a stripped param (e.g.
> two `?sessionid=` values) collapse onto **one** entry. That is the point for
> tracking junk, but it is wrong if the origin actually keys private content off
> such a param without marking it `private`/`Set-Cookie`. For those origins use a
> raw, no-strip/no-sort key so distinct queries never alias:
> `cache_turbo_key $scheme$host$request_uri;`.

```nginx
cache_turbo_key             $host$uri$cache_turbo_normalized_args;
cache_turbo_normalize_strip sid sessionid "tmp_*";
cache_turbo_normalize_vary  encoding device;   # keep gzip≠brotli, mobile≠desktop
```

## Presets (pick a vibe, skip the knobs)

Don't want to tune four numbers? Pick a preset:

```nginx
cache_turbo        ct;
cache_turbo_preset aggressive;   # long TTLs, wide stale window, eager refresh
```

| Knob | `micro` | `conservative` | `balanced` (default) | `aggressive` |
|---|---|---|---|---|
| fresh TTL (`valid`) | 1s | 30s | 60s | 300s |
| `beta` (refresh eagerness ×1000) | 1000 | 500 | 1000 | 3000 |
| `lock_ttl` | 1s | 10s | 5s | 3s |
| stale-window multiplier | ×2 | ×2 | ×4 | ×8 |
| `min_uses` (misses before storing) | 1 | 1 | 1 | **2** |

Any explicit knob (`cache_turbo_valid 120s;`) still beats the preset.

`aggressive` is the only preset that raises **`min_uses`**, to `2`: a key is
stored on its *second* cold miss, not its first, so a one-hit-wonder URL never
spends a cache entry on itself. That is the trade an operator asking for maximum
hit-rate on a long-tail site wants — but it costs one extra origin fetch for
every genuinely repeated key, so it is deliberately **not** the default. If you
want the aggressive TTLs without the admission gate, set `cache_turbo_min_uses 1`
explicitly; an explicit directive beats the band like any other knob.

The **stale window** is `valid × (multiplier − 1)`. So balanced + `valid 60s`
= fresh for 60s, then served stale for another 180s, then expired.

`micro` is the **microcaching** preset: a 1-second fresh TTL with a tight ×2
stale window and a 1s single-flight lock, so a hammered dynamic endpoint is
served from RAM for a second while the backend is hit ~once. It's exactly the
[microcaching recipe below](#microcaching-1-second-ttl-for-apis-and-php-fpm) in
one word — `cache_turbo_preset micro;` instead of spelling out `valid 1s` +
`lock_ttl 1s`. Override the TTL per-location with `cache_turbo_valid` as usual.

## Microcaching (1-second TTL for APIs and PHP-FPM)

**Microcaching** = a deliberately tiny TTL (≈1s) on otherwise-dynamic endpoints.
The page is "fresh" for only a second, so the data is near-real-time, but during
that second a burst of N requests is served from RAM and the backend is hit
**once** — and with the single-flight lock on, even the *cold* miss at the start
of each second collapses to one origin request instead of a stampede. Net effect
on a hammered `/api` or PHP app: backend load drops from "every request" to
"~one per endpoint per second", content at most ~1–2s stale.

cache-turbo runs in the ACCESS phase and captures the response in a body filter,
so it is **upstream-agnostic** — the exact same directives microcache a
`proxy_pass` API and a `fastcgi_pass` PHP-FPM app. Because only `GET` is cached,
mutations (`POST`/`PUT`/`DELETE`) always pass straight through.

```nginx
# A) JSON API behind proxy_pass — 1s microcache
location /api/ {
    cache_turbo               ct;
    cache_turbo_preset        micro;          # valid 1s + lock_ttl 1s + ×2 stale, in one word
    cache_turbo_lock          on;             # collapse a per-second burst to ONE origin hit
    cache_turbo_lock_timeout  1s;
    cache_turbo_min_uses      2;              # don't cache one-shot endpoints (optional)

    # never serve a cached body to an authenticated caller (Authorization is
    # already refused both ways; this also covers cookie sessions)
    cache_turbo_bypass        $http_authorization $cookie_session;
    cache_turbo_no_store      $http_authorization $cookie_session;

    proxy_pass http://api_upstream;
}
```

```nginx
# B) PHP-FPM (WordPress/Laravel/…) — 1s microcache
location ~ \.php$ {
    cache_turbo               ct;
    cache_turbo_preset        micro;          # valid 1s + lock_ttl 1s + ×2 stale
    cache_turbo_lock          on;

    # WP/Woo: auto-skip wp-admin, login + logged-in cookies. (Implies
    # cache_turbo_cache_control honor — see the gotcha below.)
    cache_turbo_backend       wordpress;

    # force the fixed 1s TTL instead of letting the app's Cache-Control win
    cache_turbo_cache_control respect;

    # belt-and-braces: never store a session response
    cache_turbo_no_store      $cookie_PHPSESSID;

    include      fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    fastcgi_pass unix:/run/php/php-fpm.sock;
}
```

**Microcaching gotchas:**

- **The `micro` preset keeps the window tight.** It is `valid 1s` + `lock_ttl
  1s` + a ×2 stale multiplier, so a copy is served stale for ≤1s more (≤2s old).
  Using `balanced`/`aggressive` instead widens that (×4/×8 = up to 4s/8s stale) —
  usually *not* what you want for "near-real-time". To microcache at a different
  TTL, keep `cache_turbo_preset micro` and add an explicit `cache_turbo_valid 2s;`
  (the explicit knob wins; the ×2 stale window scales with it).
- **`cache_control` mode vs a fixed TTL.** A CMS preset (`cache_turbo_backend`)
  defaults `cache_turbo_cache_control` to **honor**, so
  an app that emits `Cache-Control: max-age=600` would override your `1s`. Set
  `cache_turbo_cache_control respect;` to pin the microcache TTL regardless of
  app headers (example B). For an API that you *want* to honour its own
  `Cache-Control`, leave it on `honor` and drop the static `valid`.
- **Per-user safety.** Anything with an `Authorization` request header, or a
  response with `Set-Cookie` / `Cache-Control: private`, is never cached or
  served from cache. For cookie-session apps add an explicit
  `cache_turbo_bypass`/`cache_turbo_no_store` on the session cookie so a logged-in
  GET is never collapsed onto the anonymous slot (example A).
- **Background refresh stays on.** With `cache_turbo_background_update on` (the
  default) the once-per-second refresh is non-blocking — clients always get an
  instant answer and a 5xx during refresh leaves the last good copy in place
  (stale-if-error). Turn it off only if you need every served body strictly ≤1s
  old at the cost of one client per second waiting on the backend.

## Long-tail URLs: reach for `cache_turbo_min_uses` first

If the cache is large but the hit rate is poor, the usual cause is not the TTL —
it is **one-hit-wonder URLs**. Crawlers, tracking-parameter permutations, search
queries and deep pagination each produce a key that is requested once and never
again. Every one of them is stored, and each store evicts something that *was*
being reused. Raising `cache_turbo_valid` does not help: the problem is what gets
admitted, not how long it stays.

```nginx
cache_turbo_min_uses 2;   # store on the SECOND miss, not the first
```

A key is only stored once it has cold-missed `N` times, so a URL nobody asks for
twice never occupies the cache at all. The counter is a lightweight node (no
body), so the tail costs a slot but not memory. `2` is almost always the right
value — it removes the entire never-repeated class, and higher values mostly
delay caching for genuinely popular pages.

`cache_turbo_preset aggressive` already sets `min_uses 2` for you; every other
preset leaves it at `1`. Setting the directive explicitly beats whichever band is
in effect, in both directions.

Watch `cache_turbo_min_uses_skips_total`. It counts requests that went to the
origin *because* they were below the threshold: a large and growing number is the
long tail being kept out, which is the knob working — compare it against the hit
rate rather than reading it as a problem on its own.

Two interactions worth knowing:

- **L2 wins over the gate.** A key already in Redis/memcached is served from L2
  regardless of the local miss count — it is already proven popular, and a second
  node should not have to re-learn that.
- **It bounds attacker-chosen key cardinality.** When a visitor can steer the key
  (a search term, a cookie value folded with `cache_turbo_key_cookie`), no cap on
  the *value* bounds how many distinct keys they can mint. `min_uses` does, because
  a key minted once is never stored.

Use it with `cache_turbo_lock on`, not instead of it: `min_uses` decides what is
worth storing, single-flight decides how many requests reach the origin while a
key is being filled.

## Zone sizing under LRU pressure

The cache zone is a single shared-memory heap with a flat LRU (least-recently-used)
eviction list. Four kinds of nodes live in this heap and compete for space:

- **Entry nodes** — actual cached response bodies with metadata (one node + the response body)
- **Single-flight stubs** — temporary markers during origin fetch (metadata only, no body)
- **min_uses counters** — track cold-miss count before storing (metadata only, no body; one per unique key if `cache_turbo_min_uses > 1`)
- **L2 negative memos** — "the origin didn't have this key" records (metadata only, if `cache_turbo_l2_negative_ttl` is set)
- **Auto-Vary markers** — tiny records for two-level vary discovery (described in [Auto-Vary](#auto-vary-read-the-response-vary))

By default the LRU is one flat queue and **eviction does not distinguish between them** (see [`cache_turbo_scan_resistant`](#scan-resistant-eviction-cache_turbo_scan_resistant) to split it into two segments). A counter node holds no response body (its `data` pointer is NULL) but still consumes a full node structure, so on a long-tail workload with `cache_turbo_min_uses 2` enabled, each unique URL costs a slot — the counter saves the response body, not the key slot itself. If your zone is undersized relative to unique key cardinality, the counters and memos can starve out your actual cached entries.

**Auto-Vary markers are a second key-slot multiplier, and they share the same flat LRU as your objects.** Two-level keying stores a *tiny marker* node under the base URL key plus one full *variant* node per distinct variant seen (see [Auto-Vary](#auto-vary-read-the-response-vary)). A URL that varies across three encodings therefore holds up to four nodes — the marker plus three variant entries — where a non-varying URL holds one. On a zone under LRU pressure the markers compete for slots on equal terms with your hot object bodies: because eviction is variant-blind, a burst of cold varied URLs can evict a live marker, which forces the *next* request for that URL to re-discover the vary axis (an origin round-trip) before it can resolve to a variant again. Two consequences for sizing: (1) count each varied URL as `1 + variant_count` key slots, not one, in the cardinality term below; (2) if varied URLs dominate and you see marker churn (evictions high while origin traffic is flat), a larger zone protects markers more cheaply than any per-node tuning — the module keeps markers and objects on one heap by design, so the only lever is total zone size. `cache_turbo_scan_resistant` helps only indirectly: it shields the frequently-read (hot) segment, and a re-read marker is hot, so splitting the LRU keeps established markers out of the crawler-evicted probation segment.

**Watch for thrashing:**

When evictions spike but your origin traffic hasn't changed, the zone is too small or the hit rate is genuinely collapsing. Check the `cache_turbo_evictions_total` counter, exposed at your admin endpoint:

```console
$ curl 'localhost/_cache?format=prometheus' | grep evictions
cache_turbo_evictions_total{zone="ct"} 42000
```

A large and rapidly growing count under a stable workload signals that `min_uses` counters or young entries are being evicted faster than they can serve. The remedy is to **increase the zone size** (see sizing guidance below) or **lower `cache_turbo_min_uses`** (it is not useful on an undersized zone).

**Rough sizing:**

A node structure is **184 bytes** on a 64-bit build (`sizeof(ngx_http_cache_turbo_node_t)`: rbtree linkage, the 32-byte key, timestamps, flags, LRU linkage, and the two segmented-LRU fields). It is 184 whether or not `cache_turbo_scan_resistant` is enabled -- the fields exist unconditionally, they are simply never set to a non-zero value when the feature is off. Slab allocation rounds up and adds its own per-chunk overhead, so budget **~256 bytes per key** in practice rather than the bare struct size. This is incurred once per unique key, regardless of whether it is a counter, stub, or full entry. Add the response body byte count for each cached entry:

```
Zone size ≥ (unique_keys × ~256 bytes) + (cached_responses × avg_body_size)
```

Treat that as an order-of-magnitude starting point, not a formula to size a zone to the megabyte — slab rounding depends on your allocation size distribution, which depends on your body sizes. Measure, then adjust.

Example:

- 10,000 unique keys in your workload
- 2,000 of them cached (the other 8,000 are one-hit-wonders, admin URLs, etc.)
- Average cached body: 50 KB

```
Minimum zone ≈ (10,000 × 256 bytes) + (2,000 × 50,000 bytes)
             ≈ 2.5 MB + 100 MB ≈ 103 MB
```

Set `cache_turbo_zone name=ct 256m;` (rounding up for slab overhead + margin). Monitor `cache_turbo_evictions_total` for the first week. If it stays near zero, the zone is sized well. If it grows steadily, increase the zone size.

**Note where the key-slot cost falls.** In the example above the 8,000 uncached keys cost a node slot *whether or not* `min_uses` is set — a cold miss allocates a node either way. What `min_uses 2` changes is that those 8,000 keys never get a response **body** attached, which is the expensive part. So `min_uses` reduces body storage on a long-tail workload; it does not reduce the key-slot count, and it is not a fix for a zone that is too small to hold your key cardinality.

That is also why it is not a default: on a workload whose unique-key count alone exceeds the zone, the counter nodes are pure overhead. **You cannot predict the break-even point without measuring** — set `min_uses 2`, monitor `cache_turbo_min_uses_skips_total` (cold misses sent to origin without storing) and `cache_turbo_evictions_total` (thrashing), and adjust zone size upward or `min_uses` back to 1.

The zone minimum is enforced at `8 × ngx_pagesize` (~32 KB on most systems); your `cache_turbo_zone` size directive must be at least that.

See also: [Auto-Vary marker/variant scheme](#auto-vary-read-the-response-vary) (two-level keying on a single zone).

## Scan-resistant eviction: `cache_turbo_scan_resistant`

**Off by default.** With the flat LRU, a crawler that walks N unique URLs
evicts your entire hot set: every first store goes straight to the LRU head,
and every eviction takes the tail. The crawler's one-hit-wonder URLs are the
newest thing in the zone, so they push out the pages real users actually
request.

`cache_turbo_scan_resistant on` splits the LRU into two segments:

```nginx
location / {
    cache_turbo               ct;
    cache_turbo_scan_resistant on;                    # default protected_pct=80
    # cache_turbo_scan_resistant on protected_pct=60; # or tune it
    proxy_pass http://backend;
}
```

- A **new store enters PROBATION.** An unproven key never starts out protected.
- On its **second hit** an entry is promoted to **PROTECTED**. One hit is not
  enough -- a crawler touching each URL once can never promote anything.
- **Eviction takes the probation tail first**, and only falls through to the
  protected tail when probation is empty. That ordering is the whole mechanism:
  a scan can only evict other scan entries.
- Protected is capped at `protected_pct` of resident entries (1..99, default
  80). On overflow the protected tail is **demoted to the probation head**, not
  discarded -- a demoted-but-hot entry gets a second chance ahead of cold
  probation entries.

**Counter nodes never promote.** min_uses counters, L2 negative memos and
single-flight stubs hold bookkeeping, not content, so a miss storm cannot pin
the protected segment with nodes that carry no body.

**When it will not help.** If your working set fits comfortably in the zone,
nothing is being evicted and this changes nothing but adds a little bookkeeping.
It pays off specifically when unique-key cardinality exceeds the zone and the
access distribution is skewed -- i.e. you have a real hot set worth protecting.
Measure with `cache_turbo_evictions_total` and your hit rate before and after;
do not enable it on faith.

Turning it on changes only eviction ORDER. It never changes what is served,
what is cacheable, or any freshness decision, and `off` (or omitting the
directive) is byte-for-byte the pre-existing flat LRU.

**Turning it back off on a live zone.** A cache zone survives an `nginx -s
reload`, so an `on` -> `off` change inherits entries that were already promoted.
Those are **demoted back to probation as they are next accessed**, and any that
are never accessed again are drained by eviction once probation empties, so the
zone converges on the flat LRU rather than keeping a permanently privileged set.
The convergence is gradual, not instantaneous; restart (rather than reload) if
you need the flat LRU immediately.

## What autotune actually tunes

`cache_turbo_autotune on` makes the cache **load-adaptive**: every 30s it
measures the window's average backend regeneration cost and hit-rate, and when
the origin is genuinely under load it dials three things — then relaxes them the
first quiet window. Off by default; the freshness contract you configured is
never relaxed.

| What it tunes | Under load | Bounded by | Touches freshness? |
|---|---|---|---|
| **`beta`** (refresh eagerness) | raised from the measured cost (`beta = cost_ms/20`, ×1000) so refreshes fire earlier and smooth the load | re-clamped to the location's preset band (`beta_min..beta_max`) | no |
| **Stale window** (serve-stale grace) | widened by a load factor so a stale entry stays serveable longer before becoming a hard miss — fewer origin trips | ≤4× the configured stale window | **no — the fresh TTL is untouched; only the best-effort stale grace stretches** |
| **`lock_ttl`** (single-flight window) | widened by the same factor so a slow regen isn't re-claimed mid-flight and more requests collapse onto it | ≤4× the configured `lock_ttl` | no |

The load factor is published per-zone as `cache_turbo_autotuned_load` (×1000;
`1000` = baseline / not under load, up to `4000`). It is derived from the same
cost signal as beta — `1×` at the moderate-load threshold, rising with a slower
origin, hard-capped at `4×` — and **snaps back to `1000`** the first interval the
backend is no longer under load (low cost *or* a healthy hit-rate). So a traffic
spike that overwhelms the origin transparently buys the cache more stale-serving
headroom and tighter dogpile control, and it all reverts automatically once the
spike passes. What it will **never** do is extend the *fresh* TTL — a client is
never told "fresh" about content older than your `cache_turbo_valid` contract.

> Load-adaptation is folded into `cache_turbo_autotune on` — turning autotune
> on enables all three. If you want *only* beta tuning with a rock-fixed stale
> window, you currently get the adaptive stale/lock behaviour too (bounded ≤4×);
> the fresh-TTL guarantee is unaffected either way.

## Full example (the works)

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 512m;

    # cluster-shared L2 in Redis (optional). Inherited by everything below.
    cache_turbo_redis 127.0.0.1:6379 prefix=ct: timeout=250ms;

    server {
        listen 80;
        server_name example.com;

        location / {
            cache_turbo        ct;
            cache_turbo_preset balanced;
            cache_turbo_valid  60s;

            # collapse junk so ?utm_source=… and arg-reordering hit one slot,
            # but split real variants (gzip/brotli, mobile/desktop)
            cache_turbo_key             $host$uri$cache_turbo_normalized_args;
            cache_turbo_normalize_vary  encoding device;

            # let pages be purged in groups (needs Redis)
            cache_turbo_tag    $upstream_http_x_cache_tags;

            # adapt refresh eagerness to how slow the backend actually is
            cache_turbo_autotune on;

            proxy_pass http://127.0.0.1:8080;
        }

        # control panel: stats + purge + warm. LOCK THIS DOWN.
        location = /_cache {
            cache_turbo_admin ct;
            allow 127.0.0.1;
            deny  all;
        }

        # don't cache the admin/login area at all
        location /wp-admin/ {
            cache_turbo off;
            proxy_pass http://127.0.0.1:8080;
        }
    }
}
```

### Using the control panel

```console
# stats (JSON)
$ curl localhost/_cache
{"hits":1240,"misses":83,"stale_serves":12,"refreshes":11,"evictions":0,"l2_hits":61,"l2_misses":22,"bypasses":5,"cost_ms":34,"autotuned_beta":1700,"autotuned_load":1000}

$ curl -X POST 'localhost/_cache?key=/blog/post-42'   # drop one page
{"purged":1}

$ curl -X POST 'localhost/_cache?tag=post-42'         # drop everything tagged
{"purged":7}

$ curl -X POST 'localhost/_cache?all=1'               # nuke the whole zone
{"purged":312}

$ curl -X POST 'localhost/_cache?url=/,/blog/,/about' # pre-warm cold pages
{"warmed":3}
```

> The admin location purges the cache and `?url=` fires server-side fetches
> to local paths. Always gate it with `allow`/`deny` (or auth). Never public.

## Every directive in one place (full syntax)

A single annotated config that names **every** directive with valid syntax and
its **default** value, so you can copy a line out and change it. The values
shown *are* the defaults — a block with all of them deleted behaves identically
to one with all of them present.

> This block is a **reference, not a paste-me**. A few directives are
> mutually exclusive or context-restricted (Redis vs memcached, the `http`-only
> zone, the `location`-only admin endpoint) — see the comments and the
> [interaction matrix](#mutually-exclusive--interacting-directives) below. Lift
> the lines you need into the right context.

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    # ── http context only ───────────────────────────────────────────────
    cache_turbo_zone name=ct 256m;          # declare the shm zone (min 8 pages)

    # L2 tier — pick AT MOST ONE of the next two (mutually exclusive per block).
    # Both also valid at server/location scope; declared here they're inherited.
    cache_turbo_redis     redis://127.0.0.1:6379/0 prefix=ct: timeout=250ms
                          tls=off tls_verify=on keepalive=0 keepalive_timeout=60s;
  # cache_turbo_memcached 127.0.0.1:11211 prefix=ct: timeout=250ms;

    server {
        listen 80;
        server_name example.com;

        location / {
            # ── turn it on ──────────────────────────────────────────────
            cache_turbo                   ct;        # bind zone "ct" (or: off)
            cache_turbo_backend           wordpress; # wordpress|woocommerce|joomla|xenforo|discourse|phpbb|drupal|mediawiki|magento|shopware6|ghost|wagtail|kirby|typo3|invision|smf|vanilla|punbb|phorum|yabb|mybb|vbulletin (stackable, '|' or spaces); 'none' = off; implies cache_control honor

            # ── what is "the same page" ─────────────────────────────────
            cache_turbo_key               $host$uri$cache_turbo_normalized_args;  # the default
            cache_turbo_normalize_strip   sid sessionid "tmp_*";   # extra args to drop (trailing * = prefix; bare * = all)
            cache_turbo_normalize_vary    encoding device;        # add variant buckets to the key

            # ── freshness / staleness ───────────────────────────────────
            cache_turbo_preset            balanced;  # micro|conservative|balanced|aggressive — sets the 4 knobs below
            cache_turbo_valid             60s;       # 200 TTL; 0 = cache forever
            cache_turbo_valid             301 302 308 1h;   # repeatable: cache redirects
            cache_turbo_valid             404 410 1m;       #            negative caching
            cache_turbo_beta              1000;      # refresh eagerness ×1000
            cache_turbo_lock_ttl          5s;        # single-flight refresh window
            cache_turbo_cache_control     respect;   # respect | honor (take TTL from response CC/Expires) | ignore (discard response CC)
            cache_turbo_background_update on;        # SWR + stale-if-error (off = inline regen)
            cache_turbo_max_size          1m;        # don't cache bodies bigger than this

            # ── dogpile / admission control ─────────────────────────────
            cache_turbo_lock              on;        # cold-miss single-flight (others wait for the fill)
            cache_turbo_lock_timeout      5s;        # how long a waiter waits before going to origin itself
            cache_turbo_min_uses          1;         # cache only after the key is seen N times (1 = first miss)

            # ── per-request opt-outs ────────────────────────────────────
            cache_turbo_bypass            $cookie_session;  # skip lookup, still store
            cache_turbo_no_store          $cookie_session;  # ...so pair it, see below
            # NOT $arg_nocache -- a client-supplied bypass trigger is a DoS lever
            cache_turbo_no_store          $cookie_session;              # don't store the response

            # ── let the origin decide (inverts the store default here) ──
            cache_turbo_require_header    X-GraphQL-Cacheable;          # store ONLY if origin affirms

            # ── Vary handling ───────────────────────────────────────────
            cache_turbo_auto_vary         off;       # on = read response Vary, split automatically

            # ── L2 grouping / tuning ────────────────────────────────────
            cache_turbo_tag               $upstream_http_x_cache_tags;  # needs cache_turbo_redis
            cache_turbo_autotune          off;       # on = derive beta from measured backend latency (fixed 30s cadence)

            # ── stacking with native proxy_cache ────────────────────────
            cache_turbo_suppress_native   off;       # on = drive $cache_turbo_active for proxy_no_cache

            proxy_pass http://127.0.0.1:8080;
        }

        # ── location context only ───────────────────────────────────────
        location = /_cache {
            cache_turbo_admin ct;        # stats / purge / warm endpoint
            cache_turbo_purge on;        # also accept PURGE <uri>
            allow 127.0.0.1;
            deny  all;                   # NEVER public
        }
    }
}
```

### Mutually exclusive / interacting directives

| Pair | Relationship | What happens |
|---|---|---|
| `cache_turbo_redis` ↔ `cache_turbo_memcached` | **hard error** | One L2 per block. Declaring both in the same block fails the config at start ("the two are mutually exclusive"). |
| `cache_turbo_tag` → `cache_turbo_redis` | **requires** | Tags need Redis sorted-sets. With memcached or no L2 the tag is rejected at config time (memcached has no tag/`?all`/cross-node lock). |
| `cache_turbo_auto_vary` ↔ `cache_turbo_normalize_vary` | **don't double-cover an axis** | Not an error, but keying the same axis (e.g. `encoding`) via both multiplies the slot count for no benefit. Pick one per axis. |
| `cache_turbo_preset` ↔ `cache_turbo_valid`/`_beta`/`_lock_ttl` | **explicit wins** | The preset sets a band of defaults; any explicit knob overrides just that knob (the rest stay at the preset). Not exclusive. |
| `cache_turbo_backend` → `cache_turbo_cache_control` | **implies** | Enabling any CMS auto-classify preset defaults `cache_turbo_cache_control` to `honor` unless you set it explicitly. `none` does not — asking for no classification should not quietly change how Cache-Control is treated. |
| `cache_turbo_background_update off` → stale-if-error / SWR | **disables** | Inline regeneration replaces serve-stale-while-revalidate; a stale entry is no longer served during refresh, and stale-if-error no longer applies. |

## Directive synopsis

| Directive | Context | Default | What it does |
|---|---|---|---|
| `cache_turbo_zone name=NAME SIZE` | `http` | — | Declare a shared-memory cache zone (min 8 pages). |
| `cache_turbo NAME` / `off` | `server`, `location` | `off` | Turn caching on (bind a zone) or off. Takes a zone name and nothing else — the old `auto` shorthand is gone (see `cache_turbo_backend`). |
| `cache_turbo_backend NAME...` | `server`, `location` | — | Auto-classify dynamic (uncacheable) request surfaces for one or more CMS presets: `wordpress`, `woocommerce`, `joomla`, `xenforo`, `discourse`, `phpbb`, `drupal`, `mediawiki`, `magento`, `shopware6`, `ghost`, `wagtail`, `kirby`, `typo3`, `invision`, `smf`, `vanilla`, `punbb`, `phorum`, `yabb`, `mybb`, `vbulletin` — or `none`. A matching request (login/session cookie, admin URI, dynamic arg) skips the cache and goes straight to origin. **Every preset is opt-in**; names **stack**, separated by spaces or `\|` (`wordpress\|woocommerce` == `wordpress woocommerce`). Implies `cache_turbo_cache_control honor`. **`none`** means no preset here and exists to override one inherited from the `server` block; it is exclusive and does not imply `honor`. **`generic`/`auto` were removed** and are now a config error — the union was never a safe default ([why](#cms-backends-cache_turbo_backend)). **`joomla` and `phpbb` ship no cookie rule**; both need your own `cache_turbo_bypass` to protect logged-in users ([phpbb](docs/phpbb.md) needs a *value* test). **`wagtail`/`kirby` ship a *conditional* cookie rule** that fails safe — it stops matching if the app writes sessions for guests ([wagtail](docs/wagtail.md), [kirby](docs/kirby.md)). **`typo3` ships the same kind of conditional cookie rule, but it fails UNSAFE** — the cookie name is admin-overridable (`FE/cookieName`), and a renamed cookie means a logged-in page gets cached rather than a guest getting bypassed; add your own `cache_turbo_bypass` if you rename it ([typo3](docs/typo3.md)). **`magento` and `shopware6` value-key their vary cookie** (`X-Magento-Vary`, `sw-cache-hash`) rather than bypassing on it — the cookie's value is folded into the cache key so each vary context gets its own entry, matching each app's own Varnish VCL and built-in FPC ([magento](docs/magento.md), [shopware6](docs/shopware6.md)). **`smf`, `vanilla` and `punbb` are presence-only despite (SMF/PunBB) or possibly (Vanilla) being guest-issued** — SMF/PunBB's ideal value predicate needs array/base64 decoding this engine doesn't do; Vanilla is presence-only because guests are believed (not source-verified) to never receive it ([smf](docs/smf.md), [vanilla](docs/vanilla.md), [punbb](docs/punbb.md)). There is **no `django`/`laravel` preset** and never will be ([why](docs/frameworks.md)); there is likewise **no `bbpress`/`wpforo`/`asgaros`/`buddypress`/`buddyboss`** (fully covered by `wordpress`, [addendum](docs/wordpress.md)) or **`kunena`** (same shape as bare `joomla`, [addendum](docs/joomla.md)) preset. |
| `cache_turbo_suppress_native on` | `server`, `location` | `off` | Make `$cache_turbo_active` read `1` while cache-turbo owns a request, so a stacked native `proxy_cache` can defer via `proxy_no_cache $cache_turbo_active; proxy_cache_bypass $cache_turbo_active;`. Off (default) keeps the variable always `0` (the wiring stays inert). |
| `cache_turbo_key STRING` | `server`, `location` | normalized | What makes two requests "the same page". The default is `$host$uri$cache_turbo_normalized_args` — Host + **normalized args** (tracking params stripped, args sorted). |
| `cache_turbo_preset NAME` | `server`, `location` | `balanced` | `micro` / `conservative` / `balanced` / `aggressive` — sets the four knobs below at once. `micro` = 1s microcaching (valid 1s, lock_ttl 1s, ×2 stale). |
| `cache_turbo_valid [CODE...] TIME` | `server`, `location` | preset (`60s`) | How long a copy stays *fresh* (then *stale*, still served). Bare `TIME` = the default/200 TTL. `TIME` of `0` = cache forever (stays fresh, never expires). With leading status codes (`cache_turbo_valid 301 404 1m;`) it makes those statuses cacheable too — redirects + negative caching. Repeatable. |
| `cache_turbo_beta N` | `server`, `location` | preset (`1000`) | Refresh eagerness, ×1000 (1000 = 1.0). Higher = refresh sooner/more often. |
| `cache_turbo_lock_ttl TIME` | `server`, `location` | preset (`5s`) | Single-flight window: once one refresh is claimed, others serve stale until it finishes. Caps backend regens to ~one per cycle. |
| `cache_turbo_stale_mult N` | `server`, `location` | preset (`4` balanced) | Stale window as a multiple of the fresh TTL: an entry stays serveable as `STALE` until `cache_turbo_valid * N`. `1` = no stale window (hard-expire at the fresh TTL); the maximum is `8`. An explicit value overrides the preset's band, like `cache_turbo_valid`/`_beta`/`_lock_ttl`. `0` is rejected rather than silently meaning `4`. |
| `cache_turbo_lock on` / `off` | `server`, `location` | `on` | Cold-miss single-flight: when an *uncached* key is hit by many requests at once, the first goes to the origin and the rest **wait** for it to fill the cache (per box via a stub, cluster-wide via the Redis lock) rather than all stampeding the origin. **Off** = every cold miss goes straight to the origin. |
| `cache_turbo_lock_timeout TIME` | `server`, `location` | `5s` | How long a waiting cold-miss request waits for the winner's fill before giving up and going to the origin itself. |
| `cache_turbo_min_uses N` | `server`, `location` | preset (`1`, `2` aggressive) | Cache a page only after its key has been requested `N` times — keep one-hit-wonder URLs out of the cache. Below the threshold each request goes to the origin and is **not** stored; the `N`-th miss stores it. A key already present in the L2 (Redis or memcached) tier is served from L2 regardless (it is already proven popular). `1` = store on the first miss (off), which is the band value for every preset except `aggressive` (`2`). An explicit value overrides the preset's band, like `cache_turbo_valid`/`_beta`/`_lock_ttl`/`_stale_mult`. Range `1`..`32`; `0` and negatives are rejected at config time rather than silently meaning `1`. Note each sub-threshold miss still costs a lightweight counter node in the zone — `min_uses` saves the response *body*, not the key slot, so raising it on a site without a long tail is a pure origin-load increase. |
| `cache_turbo_scan_resistant on\|off [protected_pct=N]` | `server`, `location` | `off` | Split the LRU into PROBATION and PROTECTED segments so a crawler walking a large unique keyspace cannot evict the hot set. A new store enters probation; a **second** hit promotes to protected; eviction takes the probation tail first and only falls through to protected when probation is empty. `protected_pct` caps the protected segment as a percentage of resident entries (`1`..`99`, default `80`); on overflow the protected tail is demoted to the probation head rather than dropped. Counter/stub/memo nodes never promote (they hold no body). `off` and omitting the directive are byte-for-byte the flat LRU. `protected_pct=0`, values outside `1..99`, non-numeric values, and `protected_pct` combined with `off` are all rejected at config time rather than silently coerced. Changes eviction ORDER only -- never what is served, what is cacheable, or any freshness decision. |
| `cache_turbo_l2_negative_ttl N` | `server`, `location` | `0` (off) | Remember for `N` seconds that an L2 (Redis/memcached) `GET` missed a key, so the next cold request for it **skips the L2 round-trip** instead of paying a full RTT to be told "absent" again. Off by default and **not** a preset band value — it must be opted into explicitly, because it trades L2 coherence for that saved round-trip. Like every other `server`-scoped directive here it **inherits**: set it at `server` level and every location under it that does not override it gets the same window, so scope it to the locations you mean rather than assuming it stays where you wrote it. **Bounded staleness by construction:** nothing invalidates the memo when a *peer* node stores the key, so for up to `N` seconds this node may go to the origin for an object L2 actually holds. That is a hit-rate cost, never a correctness one — the memo carries no body and can never cause a stale serve. Keep `N` at a few seconds (the cold-key stampede it collapses is far shorter) and leave it off unless L2 misses dominate your miss path. Range `0` (off) or `1`..`60`; negatives are rejected at config time. Watch `cache_turbo_l2_neg_skips_total` against `cache_turbo_l2_hits_total` — rising skips with falling L2 hits means the window is too long. |
| `cache_turbo_max_size SIZE` | `server`, `location` | `1m` | Don't cache responses bigger than this. |
| `cache_turbo_bypass VAR...` | `server`, `location` | — | If any variable is non-empty and not `0`, skip the cache lookup (go to origin) — but still store the fresh response. E.g. `cache_turbo_bypass $cookie_session;` to always revalidate logged-in users. **Never put a client-controlled variable (`$arg_nocache`, `$http_x_no_cache`, …) in this list on a public endpoint** — the bypass returns before the single-flight lock is taken, so miss-collapsing does not apply and `ab -n 200000 'https://site/?nocache=1'` puts 100% of a flood on the origin. If you need a manual cache-buster, gate it on something only you can send (a shared secret in a header, or `$remote_addr` via a `map`). **On an identity predicate (session/login cookie, auth token, private-surface flag) always pair it with the same variables on `cache_turbo_no_store`** — on its own a bypass still writes that user's personalised response under the shared key, where the next anonymous visitor can be served it. Bypass controls the *lookup*; `cache_turbo_no_store` controls the *store*. (`cache_turbo_bypass_uri` and the `cache_turbo_backend` presets do skip storing as well; only `cache_turbo_bypass` does not.) |
| `cache_turbo_no_store VAR...` | `server`, `location` | — | If any variable is non-empty and not `0`, do **not** store the response. E.g. `cache_turbo_no_store $cookie_session;`. |
| `cache_turbo_bypass_uri PREFIX...` | `server`, `location` | — | Skip the cache entirely for requests whose URI starts with any of the listed prefixes — neither served from nor stored into the cache. Each prefix must start with `/` (a config error otherwise) and is matched against `r->uri` **with a `/` or `.` boundary**. `r->uri` is the decoded path *without* the query string, so a prefix containing `?` can never match — use `cache_turbo_bypass` with a `map $args` for query-string state. Prefixes are anchored at byte 0 and are **not** rebased by `cache_turbo_backend_prefix` (they are your own literals, written against the deployed path), so on a subdirectory install give them the full mounted paths. |
| `cache_turbo_backend_prefix PATH` | `server`, `location` | — | Declare the mount point of a **subdirectory install** (`cache_turbo_backend_prefix /shop/;` for a WordPress served from `https://example.com/shop/`). The `cache_turbo_backend` presets ship URI rules as root-relative literals (`/wp-admin/`) matched from byte 0, so without this a mounted app matches **no** URI rule at all and its admin surface is cacheable. When set and the request URI starts with `PATH`, the preset URI tier compares against the URI with the mount removed — `/shop/wp-admin/` is tested as `/wp-admin/`. Must begin and end with `/` (a config error otherwise; bare `/` is rejected as a no-op). A URI outside the mount is left alone rather than force-matched. Scope is the **preset URI tier only**: `cache_turbo_bypass_uri` prefixes are your own literals and are untouched, and the cookie and arg tiers are path-independent. Unrelated to the `prefix=` parameter on `cache_turbo_redis`/`cache_turbo_memcached`, which namespaces cache *keys*. |
| `cache_turbo_key_cookie NAME...` | `server`, `location` | — | Fold the value of each named cookie into the cache key, so each distinct value gets its own entry. Names are matched **exactly** (not as a substring). Each value is added **length-prefixed**, which is why this is the correct way to key on a cookie: splicing `$cookie_*` variables into `cache_turbo_key` by hand leaves the fields undelimited and lets a visitor choose a value that reproduces another page's key. Use for **variants** (theme, language, currency); never for identity — see `cache_turbo_bypass`. Values longer than **256 bytes** are not folded verbatim: they all collapse into a single *oversize* bucket, distinct both from the absent-cookie (anonymous) entry and from every in-range value, so an over-long value can neither poison the anonymous entry nor land on a real segment's. A cap does not bound cardinality in general — for that use `cache_turbo_min_uses`. |
| `cache_turbo_require_header NAME` | `server`, `location` | — | **Inverts the store default** on this location: nothing is stored unless the *response* carries `NAME` with an affirmative value (`yes`/`1`/`on`, case-insensitive, matched whole). Header absent, `no`, empty, or sent twice with conflicting values ⇒ no store — it **fails closed**. For origins HTTP cannot judge: a GraphQL endpoint answers queries and mutations on one URI+method and returns errors as `200` ([details](#letting-the-origin-decide-cache_turbo_require_header)). Takes a header **name**, not a `$variable` (the value is read from the response; a variable would evaluate against the request), validated at config time. Stripped before storing, so a hit never replays it. Unset ⇒ inert. |
| `cache_turbo_purge on` | `server`, `location` | `off` | Allow a `PURGE <uri>` request to drop that URI's entry from L1 (+L2). Gate the location with `allow`/`deny`. E.g. `curl -X PURGE http://host/blog/post-42`. |
| `cache_turbo_cache_control respect\|honor\|ignore` | `server`, `location` | `respect` | How the response `Cache-Control` is treated. **respect** (default): it gates storage and reshapes the stale window as written; the fresh TTL comes from `cache_turbo_valid`. **honor**: also take the fresh TTL from the response's own freshness headers, in RFC 9213 precedence order — `Surrogate-Control: max-age` (Fastly/Akamai) > `CDN-Cache-Control: s-maxage`/`max-age` (Cloudflare) > `Cache-Control: s-maxage`/`max-age` > `Expires` — falling back to `cache_turbo_valid` when none is present. The two **targeted** headers let an origin hand this shared cache a different TTL than the browser's `Cache-Control`; a targeted `no-store`/`private`/`max-age=0` also vetoes storage, and both targeted headers are stripped before store so they never replay downstream (see [Behind a CDN / multi-tier caching](#behind-a-cdn--multi-tier-caching)). **ignore**: discard the response `Cache-Control` **entirely** (mirror of nginx's `proxy_ignore_headers Cache-Control`) — `no-store`/`no-cache`/`private`/`max-age=0`/`s-maxage=0` no longer forbid storage, `must-revalidate`/`proxy-revalidate`/`stale-while-revalidate=N`/`stale-if-error=N` no longer reshape the window (it stays `cache_turbo_valid` × `cache_turbo_stale_mult`), and the TTL comes from `cache_turbo_valid`; use it for an origin that blankets shareable pages with `max-age=0, must-revalidate`. The `Set-Cookie` and request-`Authorization` safety floors are **not** affected by any mode — a per-user response is still never cached. A CMS preset (`cache_turbo_backend`) defaults this to `honor`. |
| `cache_turbo_background_update on` / `off` | `server`, `location` | `on` | The stale-while-revalidate behaviour. **On** (default): a stale page is served *immediately* while one request quietly refreshes it in the background — **nobody waits on the backend**, and if that refresh hits a 5xx/timeout the old copy is left untouched and keeps being served (**stale-if-error**). **Off**: the chosen refresher regenerates inline (it waits for the backend and serves the fresh body), the pre-SWR behaviour. |
| `cache_turbo_autotune on` | `server`, `location` | `off` | Adapt to live backend load. Auto-picks `beta` from the measured regen latency (clamped to the preset's band) **and**, under sustained load, widens two knobs by a load factor (≤4×): the **serveable stale window** (serve stale longer before a hard miss) and the **single-flight `lock_ttl`** (collapse more requests onto one regen). The **fresh** TTL is never touched — the freshness contract you set is unchanged; only the best-effort stale grace and dogpile window stretch, and they snap back the first quiet window. Recomputes on a fixed 30s cadence. See [What autotune does](#what-autotune-actually-tunes). |
| `cache_turbo_redis DSN [opts...]` | `http`, `server`, `location` | — | Add a shared **L2 Redis** tier. `DSN` is `redis://[user:pass@]host:port/db` (or bare `host:port`); `rediss://` = TLS. Write-through on store; one sync `GET` on an L1 miss (never on an L1 hit). Opts: `prefix=` (`ct:`, must be non-empty), `timeout=` (`250ms`), `password=`, `user=`, `db=`, `tls=on\|off`, `tls_verify=on\|off` (default on), `tls_ca=<file>`, `tls_name=<host>`, `keepalive=N` (idle conns to pool per worker, `0`=off), `keepalive_timeout=` (`60s`). Pooled conns are reused only within the same db/credentials/TLS context. **`keepalive=`/`keepalive_timeout=` are honoured per connection profile — each distinct backend gets its own per-worker pool sized from its own location (soft cap 16 profiles/worker).** Native client, no hiredis. |
| `cache_turbo_memcached HOST:PORT [opts...]` | `http`, `server`, `location` | — | Add a shared **L2 memcached** tier (alternative to `cache_turbo_redis`, mutually exclusive with it). Write-through on store; one sync `get` on an L1 miss. Opts: `prefix=` (`ct:`), `timeout=` (`250ms`). No tags / `?all` / cross-node lock (memcached lacks sorted sets, `SCAN`, atomic `SET-NX`); 1 MiB value cap. Native client, no libmemcached. |
| `cache_turbo_tag EXPR` | `server`, `location` | — | Tag stored pages (whitespace/comma list) so they can be purged as a group. Needs `cache_turbo_redis`. |
| `cache_turbo_admin NAME` | `location` | — | Make this location a control endpoint for zone `NAME` (stats/purge/warm). Gate with `allow`/`deny`. |
| `cache_turbo_normalize_strip NAME...` | `server`, `location` | — | Extra query args to drop from `$cache_turbo_normalized_args` (trailing `*` = prefix; a bare `*` matches every name = drop all), on top of the built-ins. |
| `cache_turbo_normalize_vary TOKEN...` | `server`, `location` | off | Append a variant bucket to `$cache_turbo_normalized_args`: `encoding` (br/gzip/identity) and/or `device` (mobile/desktop). |
| `cache_turbo_auto_vary on` | `server`, `location` | `off` | Read the response's own `Vary` header and split the cache by the named request header automatically. Safe whitelist: `Accept-Encoding`, `User-Agent` (device class), `Accept-Language` (primary-subtag class), `Origin` (raw — CORS boundary, never folded). `Vary: *`/`Cookie`/`Authorization` — **or any other header not on the whitelist** — ⇒ uncacheable (so an un-split Vary axis can never serve the wrong representation). Two-level, node-local keying. See [Auto-Vary](#auto-vary-read-the-response-vary). |

### Variables

| Variable | Value |
|---|---|
| `$cache_turbo_normalized_args` | The request's query string with tracking params stripped and the rest sorted, plus the optional Vary bucket (`cache_turbo_normalize_vary`). The default cache key's args component. |
| `$cache_turbo_active` | `1` when cache-turbo is engaged for this request (enabled, cacheable method, main request) **and** `cache_turbo_suppress_native on`; else `0`. Wire it into a stacked `proxy_cache` via `proxy_no_cache`/`proxy_cache_bypass` so the native cache defers. |
| `$cache_turbo_beta` | The effective refresh `beta` ×1000 in force for this request (preset/explicit/autotuned). Handy for debugging/logging. |
| `$cache_turbo_status` | The per-request serve outcome, for access logging. Tokens mirror nginx's `$upstream_cache_status` so the two graph together: `HIT` (served fresh), `STALE` (served stale while refreshing, incl. stale-if-error), `EXPIRED` (a cached entry was found past its serveable window and refetched from origin), `MISS` (no serveable entry anywhere → origin, or an only-if-cached request the cache couldn't satisfy → 504), `BYPASS` (`cache_turbo_bypass` or a CMS backend preset skipped to origin). `-` when cache-turbo never engaged. E.g. `log_format ct '$request "$cache_turbo_status" rt=$request_time';`. |

### Admin endpoint verbs

| Request | Effect |
|---|---|
| `GET /_cache` | JSON stats (`?autotune=1` also forces an autotune recompute first). |
| `GET /_cache?format=prometheus` | Same stats in Prometheus text format — scrape this. |
| `POST /_cache?all=1` | Purge the whole zone (and the L2 keyspace, if Redis is on). |
| `POST /_cache?key=<string>` | Purge one entry. `<string>` is hashed **verbatim**, so it must equal the entry's full cache-key value — for the default key that is `<host><uri><normalized-args>` (e.g. `example.com/blog/post-42`), **not** just the path. Use a `PURGE` request to that URL (above) if you don't want to reconstruct the key. Drops L1 + L2. |
| `POST /_cache?tag=<name>` | Purge every page tagged `<name>` across L1 + L2. |
| `POST /_cache?url=<path[,path,...]>` | Warm those paths (background prefetch). Each warm subrequest fetches **anonymously** — the admin request's `Cookie` header is stripped, so the entry is stored under the cookieless anonymous key a visitor looks up (and no per-visitor/segment body is pulled from the origin), even if you trigger the warm from a logged-in browser. |

## Monitoring (Prometheus + Grafana)

The admin endpoint speaks Prometheus. Point a scrape at it:

```console
$ curl 'localhost/_cache?format=prometheus'
# HELP cache_turbo_hits_total Fresh L1 cache hits served.
# TYPE cache_turbo_hits_total counter
cache_turbo_hits_total{zone="ct"} 1240
# TYPE cache_turbo_misses_total counter
cache_turbo_misses_total{zone="ct"} 83
cache_turbo_stale_serves_total{zone="ct"} 12
cache_turbo_refreshes_total{zone="ct"} 11
cache_turbo_evictions_total{zone="ct"} 0
cache_turbo_l2_hits_total{zone="ct"} 61
cache_turbo_l2_misses_total{zone="ct"} 22
cache_turbo_bypasses_total{zone="ct"} 5
cache_turbo_regen_cost_ms{zone="ct"} 34
cache_turbo_autotuned_beta{zone="ct"} 1700
cache_turbo_autotuned_load{zone="ct"} 1000
```

Every sample is labelled by `zone`, so one job can scrape many zones. Metrics:

| Metric | Type | Meaning |
|---|---|---|
| `cache_turbo_hits_total` | counter | Fresh hits served from RAM. |
| `cache_turbo_misses_total` | counter | Requests that fell through to the backend. |
| `cache_turbo_stale_serves_total` | counter | Old copies served during a refresh. |
| `cache_turbo_refreshes_total` | counter | Background refreshes started. |
| `cache_turbo_evictions_total` | counter | Entries dropped under memory pressure (LRU). |
| `cache_turbo_l2_hits_total` | counter | L1 misses the L2 (Redis or memcached) tier satisfied. |
| `cache_turbo_l2_misses_total` | counter | L1 misses L2 couldn't satisfy (went to origin). |
| `cache_turbo_lock_waits_total` | counter | Cold-miss requests that waited on a single-flight winner's fill. |
| `cache_turbo_min_uses_skips_total` | counter | Requests sent to origin (not stored) for being below `cache_turbo_min_uses`. |
| `cache_turbo_l2_neg_skips_total` | counter | L2 `GET`s skipped because a `cache_turbo_l2_negative_ttl` memo already recorded a miss for the key. Each unit is one L2 round-trip not taken. |
| `cache_turbo_bypasses_total` | counter | Requests skipped to origin by a `cache_turbo_bypass` predicate or a CMS backend preset (a subset of misses). |
| `cache_turbo_regen_cost_ms` | gauge | Average backend regeneration time (ms). |
| `cache_turbo_autotuned_beta` | gauge | Live autotuned `beta` ×1000 (0 = none). |
| `cache_turbo_autotuned_load` | gauge | Live load factor ×1000 widening the stale window + `lock_ttl` under load (1000 = baseline / not under load, up to 4000). |

`prometheus.yml`:

```yaml
scrape_configs:
  - job_name: cache_turbo
    metrics_path: /_cache
    params:
      format: [prometheus]
    static_configs:
      - targets: ['nginx-host:80']
```

> Same `allow`/`deny` gate applies — let your Prometheus box reach it, keep the
> public out.

A ready-made **Grafana dashboard** is in
[`tools/grafana-dashboard.json`](ci/tools/grafana-dashboard.json) — import it and
pick your Prometheus datasource (hit ratios, L1/L2 request rates, regen cost,
autotuned beta, per-`zone` template variable).

Useful PromQL: **hit ratio**
`rate(cache_turbo_hits_total[5m]) / (rate(cache_turbo_hits_total[5m]) +
rate(cache_turbo_misses_total[5m]))`, **backend regen rate**
`rate(cache_turbo_refreshes_total[5m])`, plus `cache_turbo_regen_cost_ms` and
`cache_turbo_autotuned_beta` as plain gauges.

## Redis L2 (shared cache)

By default the cache lives in each box's RAM (L1). Add Redis as a shared **L2**
so a whole fleet of nginx boxes share one cache: write-through on store, and one
`GET` on an L1 miss (L1 hits never touch Redis). Point it with a DSN:

```nginx
# plain
cache_turbo_redis redis://10.0.0.5:6379/0;

# with ACL user + password + db 2
cache_turbo_redis redis://cache:s3cret@10.0.0.5:6379/2;

# TLS (rediss://) — verifies the server cert against the system CA by default
cache_turbo_redis rediss://redis.internal:6380/0;

# TLS with a private CA, and override the verified name
cache_turbo_redis rediss://10.0.0.5:6380/0 tls_ca=/etc/ssl/redis-ca.pem tls_name=redis.internal;
```

The driver pipelines `AUTH` (+ ACL user) and `SELECT <db>` before each command;
`rediss://` wraps the socket in TLS. Any DSN field can also be given as a
trailing option, which **overrides** the DSN:

| Option | Default | Meaning |
|---|---|---|
| `password=` | — | `AUTH` password (or put it in the DSN userinfo). |
| `user=` | — | ACL username (Redis 6+). |
| `db=` | `0` | `SELECT` this db number. Must be `0`–`15`, matching Redis's default `databases 16`; a larger index is rejected at config time rather than failing every L2 op at runtime. Same bound applies to the `/N` suffix of a DSN. |
| `tls=on\|off` | from scheme | Force TLS on/off regardless of `redis://`/`rediss://`. |
| `tls_verify=on\|off` | `on` | Verify the server cert + hostname. **Leave on** unless you know why. |
| `tls_ca=<file>` | system CAs | CA bundle to trust (for a private CA). |
| `tls_name=<host>` | DSN host | Name used for SNI + cert verification. |
| `prefix=` | `ct:` | Key prefix in Redis. |
| `timeout=` | `250ms` | Connect/read timeout. |
| `keepalive=N` | `0` (off) | Idle connections pooled per worker for reuse. A pooled conn is reused only within the same db/credentials/TLS context. `0` opens a fresh connection per op. **Sized per connection profile — see the note below.** |
| `keepalive_timeout=` | `60s` | How long an idle pooled connection is kept before it is closed. **Per connection profile — see the note below.** |

> **`keepalive=` and `keepalive_timeout=` are honoured per connection
> profile.** Each distinct backend profile — host/port, db, credentials, and TLS
> context — gets its **own** idle-connection pool in each worker, with its own
> `keepalive=` size and `keepalive_timeout=`, taken from the location that opens
> that profile. Locations that share a profile share (and reuse) its pool, which
> is normal and desirable; incompatible profiles are fully isolated, each with
> its own budget, so distinct backends **cannot starve each other** and no
> connection can leak between them. A location with `keepalive=0` simply opens a
> fresh connection per op.
>
> There is a soft cap of **16 distinct pooled profiles per worker**; realistic
> deployments use one to three. A configuration that exceeds it runs the extra
> profiles unpooled (a fresh connection per op) rather than failing — safe, since
> L2 is advisory.

> TLS needs nginx built with `--with-http_ssl_module` (the stock `nginx`
> package is). Without it, a `rediss://` / `tls=on` config is rejected at start.
> Passwords sit in your nginx config — keep it `chmod 600` / out of git.

### memcached L2 (alternative backend)

If you already run **memcached** as your shared cache, point the L2 tier at it
instead of Redis with `cache_turbo_memcached` — same write-through-on-store /
sync-`GET`-on-L1-miss model, native client (no `libmemcached`):

```nginx
cache_turbo_memcached 127.0.0.1:11211 prefix=mc: timeout=250ms;
```

memcached is deliberately the *lean* L2: it has no sorted sets, no `SCAN`, and
no atomic `SET-NX`, so the features that need those are **unavailable** on it —
**tag purge** (`cache_turbo_tag`, `POST /_cache?tag=`), **whole-keyspace
purge** (`POST /_cache?all=1` clears L1 only), and the **cross-node
single-flight lock** (per-box single-flight still works). Single-key purge,
write-through, cross-instance fill and stale-while-revalidate all work as with
Redis. Values at/above memcached's 1 MiB item ceiling are skipped (the page
stays L1-only). Use Redis if you need tags or cluster-wide dogpile protection;
use memcached if you already run one and want a simple shared object tier.
`cache_turbo_redis` and `cache_turbo_memcached` are mutually exclusive in the
same block.

## Building & the stack

It's a normal dynamic module:

```console
$ ./configure --add-dynamic-module=/path/to/nginx-cache-turbo-module
$ make modules
```

No external libraries — the Redis client is hand-rolled on nginx's own event
loop. Builds against **nginx and Angie**.

**Prebuilt, in the deb.myguard.nl nginx/angie stack.** Rather than build it
yourself, install the packaged module from the
[deb.myguard.nl](https://deb.myguard.nl) APT repository — it's shipped and
kept current alongside the hardened HTTP/3 nginx / Angie builds and their full
dynamic-module set:

```console
# nginx
$ apt install libnginx-mod-http-cache-turbo
# Angie
$ apt install angie-module-http-cache-turbo
```

- **Module catalogues:** [nginx modules](https://deb.myguard.nl/nginx-modules/)
  · [Angie modules (optimized & extended)](https://deb.myguard.nl/angie-modules-optimized-extended/)
- **Directive synopsis:** [modules-synopsis #http-cache-turbo](https://deb.myguard.nl/nginx/modules-synopsis/#http-cache-turbo)
- **Writeup:** [nginx-cache-turbo — a built-in page cache](https://deb.myguard.nl/articles/nginx-cache-turbo/)

## Benchmarking

[`tools/bench.sh`](ci/tools/bench.sh) measures throughput/latency and compares
cache-turbo against the alternatives. It stands up an origin plus four edges on
separate ports — **A** origin direct (the floor), **B** nginx `proxy_cache`,
**C** cache_turbo L1 shm, **D** cache_turbo + L2 Redis — primes each so the run
hits the cache (not the origin), then drives `wrk --latency` and prints an
rps / p50 / p99 / hit-ratio table. The hit-ratio column comes from the module's
own Prometheus counters, so a "fast" run that secretly missed shows up as
< 100 % instead of as a bogus number.

```console
$ eval "$(ci/tools/ci-build.sh nginx 1.31.1 nginx)"      # stock-O release: exports binary= module=
$ MODULE="$module" ci/tools/bench.sh "$binary" 15 8       # 15s/run, 8 conns
$ SIZES="tiny medium large" REDIS="redis://127.0.0.1:6379/0" \
      MODULE="$module" ci/tools/bench.sh "$binary" 15 8   # all sizes + the L2-Redis run
```

> Build the nginx binary as a **release** build (stock `-O`, **no** `-fsanitize`,
> no valgrind) — sanitizers slow serving 10–50× and measure nothing real. That is
> [`tools/soak.sh`](ci/tools/soak.sh)'s job: it proves the module *survives* heavy
> churn under ASAN/valgrind; bench.sh proves how *fast* it serves.

Full method, the reference environment, a result set (cache-turbo **+23–37 %**
over nginx's own `proxy_cache` on small/medium bodies, ~10 % on multi-megabyte
bodies), and the caveats are in **[BENCHMARK.md](BENCHMARK.md)**.

## License

BSD-2-Clause — the same license as nginx and Angie, the servers this module is
built to load into. See [LICENSE](LICENSE).
