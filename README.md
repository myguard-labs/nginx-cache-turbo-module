# nginx-cache-turbo-module

A built-in page cache for nginx. Think of it as a tiny Varnish that lives
**inside** nginx — no extra daemon, no second port, no Lua.

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
$ curl -sI localhost/ | grep -i x-cache      # 1st time: nothing (it was a miss)
$ curl -sI localhost/ | grep -i x-cache
X-Cache: HIT                                  # 2nd time: served from RAM
```

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
```

And it **refuses** to cache anything that looks per-user, so you don't
accidentally serve Alice's logged-in page to Bob:

- request had an `Authorization` header → not cached
- response sets a cookie (`Set-Cookie`) → not cached
- response says `Cache-Control: private | no-store | no-cache | max-age=0 |
  s-maxage=0` → not cached

Hop-by-hop / framing headers (`Connection`, `Transfer-Encoding`,
`Content-Length`, `Set-Cookie`, `Date`, `Server`, …) are stripped before
storing; nginx rebuilds them on the way out, so a cached response is still
well-formed.

### Conditional requests (`304 Not Modified`)

If the origin gave the cached `200` an `ETag` or `Last-Modified`, the module
answers conditional requests straight from cache — no body, no origin round
trip. A `GET`/`HEAD` carrying `If-None-Match` (matched with the weak comparator,
`*` matches any cached entry) or `If-Modified-Since` gets a `304 Not Modified`
when the client's copy is still current; `If-None-Match` wins when both are
present (RFC 7232). Anything else serves the full cached body. This is automatic
— there is no directive to set.

### Auto-Vary (read the response `Vary`)

Turn on `cache_turbo_auto_vary on` and the module reads the response's own
`Vary` header and splits the cache by the named **request** header automatically
— no need to pre-declare the axes. It honours a safe whitelist:
`Accept-Encoding` (bucketed br/gzip/identity/zstd), `User-Agent` (mobile/desktop
class), `Accept-Language` and `Origin` (raw value). A response with `Vary: *`, or
one that varies on `Cookie` or `Authorization`, is treated as **uncacheable**
(those vary per-user — caching them would poison or leak across users); any other
named header is ignored (still cached, just not split on it).

Keying is two-level and node-local: the first time a URL's response is seen to
vary, the module records a tiny *vary marker* in L1 and stores the body under a
secondary *variant* key; later requests read the marker and resolve straight to
their variant. The base slot stays empty for varied URLs, so a node that hasn't
learned the `Vary` yet simply misses to origin — it never serves the wrong
variant. Off by default.

> ⚠️ With auto-Vary **off**, the cache keys on the **request**, not on the
> response's `Vary`. If your page differs by gzip-vs-brotli or
> mobile-vs-desktop, either turn on `cache_turbo_auto_vary` or split the key
> yourself with `cache_turbo_normalize_vary` (below) — otherwise the first
> variant stored wins for everyone.

## The cache key

A "key" is just the string that decides whether two requests are *the same
page*. Default key is `$host$request_uri` (the Host + the full path+query), so
two vhosts sharing a zone never collide.

Set your own with `cache_turbo_key` using any nginx variables:

```nginx
cache_turbo_key $scheme$host$uri$is_args$args;
```

## Presets (pick a vibe, skip the knobs)

Don't want to tune four numbers? Pick a preset:

```nginx
cache_turbo        ct;
cache_turbo_preset aggressive;   # long TTLs, wide stale window, eager refresh
```

| Knob | `conservative` | `balanced` (default) | `aggressive` |
|---|---|---|---|
| fresh TTL (`valid`) | 30s | 60s | 300s |
| `beta` (refresh eagerness ×1000) | 500 | 1000 | 3000 |
| `lock_ttl` | 10s | 5s | 3s |
| stale-window multiplier | ×2 | ×4 | ×8 |

Any explicit knob (`cache_turbo_valid 120s;`) still beats the preset.

The **stale window** is `valid × (multiplier − 1)`. So balanced + `valid 60s`
= fresh for 60s, then served stale for another 180s, then expired.

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
{"hits":1240,"misses":83,"stale_serves":12,"refreshes":11,"evictions":0,"l2_hits":61,"l2_misses":22,"cost_ms":34,"autotuned_beta":1700}

$ curl -X POST 'localhost/_cache?key=/blog/post-42'   # drop one page
{"purged":1}

$ curl -X POST 'localhost/_cache?tag=post-42'         # drop everything tagged
{"purged":7}

$ curl -X POST 'localhost/_cache?all=1'               # nuke the whole zone
{"purged":312}

$ curl -X POST 'localhost/_cache?url=/,/blog/,/about' # pre-warm cold pages
{"warmed":3}
```

> ⚠️ The admin location purges the cache and `?url=` fires server-side fetches
> to local paths. Always gate it with `allow`/`deny` (or auth). Never public.

## Directive synopsis

| Directive | Context | Default | What it does |
|---|---|---|---|
| `cache_turbo_zone name=NAME SIZE` | `http` | — | Declare a shared-memory cache zone (min 8 pages). |
| `cache_turbo NAME` / `off` | `server`, `location` | `off` | Turn caching on (bind a zone) or off. |
| `cache_turbo_key STRING` | `server`, `location` | `$host$uri$cache_turbo_normalized_args` | What makes two requests "the same page". The default already includes the Host and the **normalized args** (tracking params stripped, args sorted). |
| `cache_turbo_preset NAME` | `server`, `location` | `balanced` | `conservative` / `balanced` / `aggressive` — sets the four knobs below at once. |
| `cache_turbo_valid [CODE...] TIME` | `server`, `location` | preset (`60s`) | How long a copy stays *fresh* (then *stale*, still served). Bare `TIME` = the default/200 TTL. With leading status codes (`cache_turbo_valid 301 404 1m;`) it makes those statuses cacheable too — redirects + negative caching. Repeatable. |
| `cache_turbo_beta N` | `server`, `location` | preset (`1000`) | Refresh eagerness, ×1000 (1000 = 1.0). Higher = refresh sooner/more often. |
| `cache_turbo_lock_ttl TIME` | `server`, `location` | preset (`5s`) | Single-flight window: once one refresh is claimed, others serve stale until it finishes. Caps backend regens to ~one per cycle. |
| `cache_turbo_lock on` / `off` | `server`, `location` | `on` | Cold-miss single-flight: when an *uncached* key is hit by many requests at once, the first goes to the origin and the rest **wait** for it to fill the cache (per box via a stub, cluster-wide via the Redis lock) rather than all stampeding the origin. **Off** = every cold miss goes straight to the origin. |
| `cache_turbo_lock_timeout TIME` | `server`, `location` | `5s` | How long a waiting cold-miss request waits for the winner's fill before giving up and going to the origin itself. |
| `cache_turbo_min_uses N` | `server`, `location` | `1` | Cache a page only after its key has been requested `N` times — keep one-hit-wonder URLs out of the cache. Below the threshold each request goes to the origin and is **not** stored; the `N`-th miss stores it. A key already present in the L2 (Redis) tier is served from L2 regardless (it is already proven popular). `1` = store on the first miss (off). |
| `cache_turbo_max_size SIZE` | `server`, `location` | `1m` | Don't cache responses bigger than this. |
| `cache_turbo_bypass VAR...` | `server`, `location` | — | If any variable is non-empty and not `0`, skip the cache lookup (go to origin) — but still store the fresh response. E.g. `cache_turbo_bypass $cookie_session $arg_nocache;` to always revalidate logged-in users. |
| `cache_turbo_no_store VAR...` | `server`, `location` | — | If any variable is non-empty and not `0`, do **not** store the response. E.g. `cache_turbo_no_store $cookie_session;`. |
| `cache_turbo_purge on` | `server`, `location` | `off` | Allow a `PURGE <uri>` request to drop that URI's entry from L1 (+L2). Gate the location with `allow`/`deny`. E.g. `curl -X PURGE http://host/blog/post-42`. |
| `cache_turbo_honor_cache_control on` | `server`, `location` | `off` | Take the fresh TTL from the response's own `Cache-Control: s-maxage`/`max-age` (s-maxage wins), or its `Expires`, instead of the static TTL. Falls back to `cache_turbo_valid` when the response carries no freshness info. |
| `cache_turbo_background_update on` / `off` | `server`, `location` | `on` | The stale-while-revalidate behaviour. **On** (default): a stale page is served *immediately* while one request quietly refreshes it in the background — **nobody waits on the backend**, and if that refresh hits a 5xx/timeout the old copy is left untouched and keeps being served (**stale-if-error**). **Off**: the chosen refresher regenerates inline (it waits for the backend and serves the fresh body), the pre-SWR behaviour. |
| `cache_turbo_autotune on` | `server`, `location` | `off` | Auto-pick `beta` from the measured backend latency, clamped to the preset's band. |
| `cache_turbo_autotune_interval TIME` | `server`, `location` | `30s` | How often autotune recomputes. |
| `cache_turbo_redis DSN [opts...]` | `http`, `server`, `location` | — | Add a shared **L2 Redis** tier. `DSN` is `redis://[user:pass@]host:port/db` (or bare `host:port`); `rediss://` = TLS. Write-through on store; one sync `GET` on an L1 miss (never on an L1 hit). Opts: `prefix=` (`ct:`), `timeout=` (`250ms`), `password=`, `user=`, `db=`, `tls=on\|off`, `tls_verify=on\|off` (default on), `tls_ca=<file>`, `tls_name=<host>`. Native client, no hiredis. |
| `cache_turbo_tag EXPR` | `server`, `location` | — | Tag stored pages (whitespace/comma list) so they can be purged as a group. Needs `cache_turbo_redis`. |
| `cache_turbo_admin NAME` | `location` | — | Make this location a control endpoint for zone `NAME` (stats/purge/warm). Gate with `allow`/`deny`. |
| `cache_turbo_normalize_strip NAME...` | `server`, `location` | — | Extra query args to drop from `$cache_turbo_normalized_args` (trailing `*` = prefix), on top of the built-ins. |
| `cache_turbo_normalize_strip_all on` | `server`, `location` | `off` | Drop **every** query arg from `$cache_turbo_normalized_args`. |
| `cache_turbo_normalize_vary TOKEN...` | `server`, `location` | off | Append a variant bucket to `$cache_turbo_normalized_args`: `encoding` (br/gzip/identity) and/or `device` (mobile/desktop). |
| `cache_turbo_auto_vary on` | `server`, `location` | `off` | Read the response's own `Vary` header and split the cache by the named request header automatically. Safe whitelist: `Accept-Encoding`, `User-Agent` (device class), `Accept-Language`, `Origin`. `Vary: *`/`Cookie`/`Authorization` ⇒ uncacheable; other names ignored. Two-level, node-local keying. See [Auto-Vary](#auto-vary-read-the-response-vary). |

### Admin endpoint verbs

| Request | Effect |
|---|---|
| `GET /_cache` | JSON stats (`?autotune=1` also forces an autotune recompute first). |
| `GET /_cache?format=prometheus` | Same stats in Prometheus text format — scrape this. |
| `POST /_cache?all=1` | Purge the whole zone (and the L2 keyspace, if Redis is on). |
| `POST /_cache?key=<string>` | Purge one entry (hashed like the cache key). Drops L1 + L2. |
| `POST /_cache?tag=<name>` | Purge every page tagged `<name>` across L1 + L2. |
| `POST /_cache?url=<path[,path,...]>` | Warm those paths (background prefetch). |

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
cache_turbo_regen_cost_ms{zone="ct"} 34
cache_turbo_autotuned_beta{zone="ct"} 1700
```

Every sample is labelled by `zone`, so one job can scrape many zones. Metrics:

| Metric | Type | Meaning |
|---|---|---|
| `cache_turbo_hits_total` | counter | Fresh hits served from RAM. |
| `cache_turbo_misses_total` | counter | Requests that fell through to the backend. |
| `cache_turbo_stale_serves_total` | counter | Old copies served during a refresh. |
| `cache_turbo_refreshes_total` | counter | Background refreshes started. |
| `cache_turbo_evictions_total` | counter | Entries dropped under memory pressure (LRU). |
| `cache_turbo_l2_hits_total` | counter | L1 misses the L2 (Redis) tier satisfied. |
| `cache_turbo_l2_misses_total` | counter | L1 misses L2 couldn't satisfy (went to origin). |
| `cache_turbo_regen_cost_ms` | gauge | Average backend regeneration time (ms). |
| `cache_turbo_autotuned_beta` | gauge | Live autotuned `beta` ×1000 (0 = none). |

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
[`tools/grafana-dashboard.json`](tools/grafana-dashboard.json) — import it and
pick your Prometheus datasource (hit ratios, L1/L2 request rates, regen cost,
autotuned beta, per-`zone` template variable).

Useful PromQL: **hit ratio**
`rate(cache_turbo_hits_total[5m]) / (rate(cache_turbo_hits_total[5m]) +
rate(cache_turbo_misses_total[5m]))`, **backend regen rate**
`rate(cache_turbo_refreshes_total[5m])`, plus `cache_turbo_regen_cost_ms` and
`cache_turbo_autotuned_beta` as plain gauges.

### Variables

| Variable | Meaning |
|---|---|
| `$cache_turbo_normalized_args` | The query string with tracking junk dropped, args sorted, plus any `normalize_vary` buckets — drop it in your `cache_turbo_key`. |
| `$cache_turbo_beta` | The `beta` this request would actually use right now (handy to `add_header X-CT-Beta $cache_turbo_beta;` and watch autotune work). |

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
| `db=` | `0` | `SELECT` this db number. |
| `tls=on\|off` | from scheme | Force TLS on/off regardless of `redis://`/`rediss://`. |
| `tls_verify=on\|off` | `on` | Verify the server cert + hostname. **Leave on** unless you know why. |
| `tls_ca=<file>` | system CAs | CA bundle to trust (for a private CA). |
| `tls_name=<host>` | DSN host | Name used for SNI + cert verification. |
| `prefix=` | `ct:` | Key prefix in Redis. |
| `timeout=` | `250ms` | Connect/read timeout. |

> TLS needs nginx built with `--with-http_ssl_module` (the stock `nginx`
> package is). Without it, a `rediss://` / `tls=on` config is rejected at start.
> Passwords sit in your nginx config — keep it `chmod 600` / out of git.

## Cache-key normalization

`$cache_turbo_normalized_args` rebuilds the query string so equivalent requests
share one slot: it sorts args (`?b=2&a=1` == `?a=1&b=2`) and drops tracking
params (built-in denylist: `utm_*`, `fbclid`, `gclid`, `msclkid`, `mc_eid`,
`_ga`, `ref`, `sid`, `sessionid`, `tmp_*`). Add more with
`cache_turbo_normalize_strip`, or nuke them all
with `cache_turbo_normalize_strip_all on`.

```nginx
cache_turbo_key             $host$uri$cache_turbo_normalized_args;
cache_turbo_normalize_strip sid sessionid "tmp_*";
cache_turbo_normalize_vary  encoding device;   # keep gzip≠brotli, mobile≠desktop
```

## Building

It's a normal dynamic module:

```console
$ ./configure --add-dynamic-module=/path/to/nginx-cache-turbo-module
$ make modules
```

No external libraries — the Redis client is hand-rolled on nginx's own event
loop. Builds against nginx and angie.

## License

MIT. See [LICENSE](LICENSE).
