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

That's it. Curl it twice and look at the `X-Cache` header:

```console
$ curl -sI localhost/ | grep -i x-cache      # 1st time: nothing (it was a miss)
$ curl -sI localhost/ | grep -i x-cache
X-Cache: HIT                                  # 2nd time: served from RAM
```

`X-Cache: HIT` = fresh from cache. `X-Cache: STALE` = old copy while a refresh
runs. No header = it went to the backend (a miss).

## What it will and won't cache

It only stores a `200 OK` to a `GET`/`HEAD`. And it **refuses** to cache
anything that looks per-user, so you don't accidentally serve Alice's logged-in
page to Bob:

- request had an `Authorization` header → not cached
- response sets a cookie (`Set-Cookie`) → not cached
- response says `Cache-Control: private | no-store | no-cache | max-age=0 |
  s-maxage=0` → not cached

Hop-by-hop / framing headers (`Connection`, `Transfer-Encoding`,
`Content-Length`, `Set-Cookie`, `Date`, `Server`, …) are stripped before
storing; nginx rebuilds them on the way out, so a cached response is still
well-formed.

> ⚠️ The cache keys on the **request**, not on the response's `Vary`. If your
> page differs by gzip-vs-brotli or mobile-vs-desktop, split the key yourself
> with `cache_turbo_normalize_vary` (below) — otherwise the first variant stored
> wins for everyone.

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
{"hits":1240,"misses":83,"stale_serves":12,"refreshes":11,"evictions":0,"cost_ms":34,"autotuned_beta":1700}

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
| `cache_turbo_key STRING` | `server`, `location` | `$host$request_uri` | What makes two requests "the same page". |
| `cache_turbo_preset NAME` | `server`, `location` | `balanced` | `conservative` / `balanced` / `aggressive` — sets the four knobs below at once. |
| `cache_turbo_valid TIME` | `server`, `location` | preset (`60s`) | How long a copy stays *fresh*. After this it's *stale* (still served). |
| `cache_turbo_beta N` | `server`, `location` | preset (`1000`) | Refresh eagerness, ×1000 (1000 = 1.0). Higher = refresh sooner/more often. |
| `cache_turbo_lock_ttl TIME` | `server`, `location` | preset (`5s`) | Single-flight window: once one refresh is claimed, others serve stale until it finishes. Caps backend regens to ~one per cycle. |
| `cache_turbo_max_size SIZE` | `server`, `location` | `1m` | Don't cache responses bigger than this. |
| `cache_turbo_autotune on` | `server`, `location` | `off` | Auto-pick `beta` from the measured backend latency, clamped to the preset's band. |
| `cache_turbo_autotune_interval TIME` | `server`, `location` | `30s` | How often autotune recomputes. |
| `cache_turbo_redis HOST:PORT [prefix=STR] [timeout=TIME]` | `http`, `server`, `location` | — | Add a shared **L2 Redis** tier. Write-through on store; one sync `GET` on an L1 miss (never on an L1 hit). `prefix` default `ct:`, `timeout` default `250ms`. Native client, no hiredis. |
| `cache_turbo_tag EXPR` | `server`, `location` | — | Tag stored pages (whitespace/comma list) so they can be purged as a group. Needs `cache_turbo_redis`. |
| `cache_turbo_admin NAME` | `location` | — | Make this location a control endpoint for zone `NAME` (stats/purge/warm). Gate with `allow`/`deny`. |
| `cache_turbo_normalize_strip NAME...` | `server`, `location` | — | Extra query args to drop from `$cache_turbo_normalized_args` (trailing `*` = prefix), on top of the built-ins. |
| `cache_turbo_normalize_strip_all on` | `server`, `location` | `off` | Drop **every** query arg from `$cache_turbo_normalized_args`. |
| `cache_turbo_normalize_vary TOKEN...` | `server`, `location` | off | Append a variant bucket to `$cache_turbo_normalized_args`: `encoding` (br/gzip/identity) and/or `device` (mobile/desktop). |

### Admin endpoint verbs

| Request | Effect |
|---|---|
| `GET /_cache` | JSON stats (`?autotune=1` also forces an autotune recompute first). |
| `POST /_cache?all=1` | Purge the whole zone (and the L2 keyspace, if Redis is on). |
| `POST /_cache?key=<string>` | Purge one entry (hashed like the cache key). Drops L1 + L2. |
| `POST /_cache?tag=<name>` | Purge every page tagged `<name>` across L1 + L2. |
| `POST /_cache?url=<path[,path,...]>` | Warm those paths (background prefetch). |

### Variables

| Variable | Meaning |
|---|---|
| `$cache_turbo_normalized_args` | The query string with tracking junk dropped, args sorted, plus any `normalize_vary` buckets — drop it in your `cache_turbo_key`. |
| `$cache_turbo_beta` | The `beta` this request would actually use right now (handy to `add_header X-CT-Beta $cache_turbo_beta;` and watch autotune work). |

## Cache-key normalization

`$cache_turbo_normalized_args` rebuilds the query string so equivalent requests
share one slot: it sorts args (`?b=2&a=1` == `?a=1&b=2`) and drops tracking
params (built-in denylist: `utm_*`, `fbclid`, `gclid`, `msclkid`, `mc_eid`,
`_ga`, `ref`). Add more with `cache_turbo_normalize_strip`, or nuke them all
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
