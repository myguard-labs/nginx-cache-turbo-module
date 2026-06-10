# nginx-cache-turbo-module

A Varnish-grade edge page cache for NGINX, in plain C. No Lua, no extra daemon.

## What is this?

NGINX already ships `proxy_cache` / `fastcgi_cache`. They cache to disk and they
work — but they're conservative. When a hot page expires, every request that
arrives in that instant stampedes the origin at once (the "dogpile" / "thundering
herd"), and a slow backend means a slow first byte for whoever loses the race.

`cache-turbo` is a from-scratch cache that fixes exactly that. It keeps responses
in a shared-memory zone (RAM, not disk) and adds the semantics you normally only
get from Varnish or a CDN:

- **Stale-while-revalidate** — when a cached page goes stale it is still served
  *instantly*. The refresh happens out of band, so visitors never wait for the
  origin during a refresh.
- **Probabilistic single-flight refresh** — across all the readers hitting a
  stale page, *one* is chosen (by a weighted dice roll) to regenerate it; the
  rest keep getting the stale copy. No locks on the read path, no stampede. This
  is the XFetch-style algorithm, ported from the sibling
  [wp-redis](#see-also) object-cache plugin so the two tools tune the same way.
- **Full-fidelity caching** — status line, `Content-Type`, and every response
  header are stored and replayed, so a cache hit is byte-identical to the origin.
- **`X-Cache` debug header** — every response is tagged `HIT`, `STALE`, or
  absent (miss) so you can see what the cache did.

It is the spiritual successor to `srcache` + `memc`: same "decouple the cache
from the backend" idea, but with the modern cache semantics srcache never had.

> **Status: v2c (alpha).** Working and tested (debug + ASan/UBSan + valgrind):
> L1 shared-memory cache with SWR + probabilistic refresh, full header fidelity,
> a REST admin API, native Redis L2 (shared/multi-node, no hiredis), and
> tag-based + L2-aware purge. Smart key normalisation, cache warming, and the
> conservative/balanced/aggressive autotune presets are on the roadmap below.

## Quick start

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    # one shared-memory zone, 256 MB of hot cache
    cache_turbo_zone name=ct 256m;

    server {
        location / {
            cache_turbo          ct;            # enable + bind the zone
            cache_turbo_key      $scheme$host$uri$is_args$args;
            cache_turbo_valid    10s;           # fresh TTL
            cache_turbo_beta     1000;          # SWR aggressiveness (×1000)
            cache_turbo_max_size 1m;            # don't cache responses bigger than this

            proxy_pass http://backend;
        }
    }
}
```

Hit the same URL twice: the first is a `MISS` (goes to the origin), the second
is a `HIT` served from RAM in microseconds. Let it go stale and you'll see
`X-Cache: STALE` while exactly one request quietly refreshes it.

## Directives

| Directive | Context | Default | Description |
|---|---|---|---|
| `cache_turbo_zone name=NAME SIZE` | `http` | — | Declare a shared-memory cache zone (min 8 pages). |
| `cache_turbo NAME` / `off` | `server`, `location` | `off` | Enable caching in this block and bind it to a zone. |
| `cache_turbo_key STRING` | `server`, `location` | `$uri` | The cache key (any nginx variables). |
| `cache_turbo_preset NAME` | `server`, `location` | `balanced` | Tuning preset: `conservative`, `balanced`, or `aggressive`. Sets the defaults for `cache_turbo_valid`, `cache_turbo_beta`, `cache_turbo_lock_ttl` and the stale-window multiplier in one shot. An explicit knob directive still wins over the preset. See [Presets](#presets). |
| `cache_turbo_valid TIME` | `server`, `location` | preset (`60s` balanced) | Fresh TTL. After this the entry is *stale* (still served). |
| `cache_turbo_beta N` | `server`, `location` | preset (`1000` balanced) | SWR refresh aggressiveness, fixed-point ×1000 (1000 = 1.0). Higher → refresh earlier/more often. |
| `cache_turbo_lock_ttl TIME` | `server`, `location` | preset (`5s` balanced) | Hard single-flight window: once a refresh is claimed, all readers serve stale (skip the dice) until this expires or the refresh completes. Caps origin regens to ~one per stale cycle. |
| `cache_turbo_max_size SIZE` | `server`, `location` | `1m` | Largest single response to cache. |
| `cache_turbo_redis HOST:PORT [prefix=STR] [timeout=TIME]` | `http`, `server`, `location` | — | Add a shared **L2 Redis** tier behind the L1 shm cache. Stores write through asynchronously; an L1 miss does one synchronous Redis `GET` (off the hot path — L1 hits never touch Redis) and fills L1 on a hit. `prefix` defaults to `ct:`, `timeout` to `250ms`. Native client, no hiredis. |
| `cache_turbo_tag EXPR` | `server`, `location` | — | Tag stored objects so they can be purged as a group. `EXPR` (any nginx variables) yields a whitespace/comma list of tags — e.g. `cache_turbo_tag $upstream_http_x_cache_tags`. Each tag set is kept in L2, so this needs `cache_turbo_redis`. Purge with `POST ?tag=<name>`. |
| `cache_turbo_admin NAME` | `location` | — | Turn this location into a control endpoint for zone `NAME`. `GET` returns JSON stats; `POST ?all=1` purges the zone, `POST ?key=<string>` purges one key, `POST ?tag=<name>` purges every object carrying that tag, `POST ?url=<path[,path...]>` **warms** the cache for those paths (background prefetch). With `cache_turbo_redis` on the admin location, `?key`/`?tag` drop the entry from **both** L1 and L2. Gate it with `allow`/`deny`. |
| `cache_turbo_normalize_strip NAME...` | `server`, `location` | — | Extra query-arg names to drop from `$cache_turbo_normalized_args`, **added** to the built-in denylist. A trailing `*` is a prefix match (e.g. `tmp_*`). |
| `cache_turbo_normalize_strip_all on` | `server`, `location` | `off` | Drop **every** query arg from `$cache_turbo_normalized_args` (the variable becomes the empty string). |

### Admin endpoint

```nginx
location = /_cache {
    cache_turbo_admin main;
    allow 127.0.0.1;
    deny all;
}
```

```console
$ curl localhost/_cache
{"hits":1240,"misses":83,"stale_serves":12,"refreshes":11,"evictions":0}

$ curl -X POST 'localhost/_cache?key=/blog/post-42'
{"purged":1}

$ curl -X POST 'localhost/_cache?tag=blog'
{"purged":37}

$ curl -X POST 'localhost/_cache?all=1'
{"purged":204}
```

Add `cache_turbo_redis` to the admin location (inherited from `server`/`http`
is fine) so `?key` and `?tag` purges clear the **L2** tier too — otherwise a
purged entry just refills from Redis on the next miss.

### Cache warming

`POST ?url=<path[,path,...]>` pre-populates the cache for one or more site
paths, so a cold URL is a **HIT** on its first real visitor instead of a miss:

```console
$ curl -X POST 'localhost/_cache?url=/blog/post-42'
{"warmed":1}

$ curl -X POST 'localhost/_cache?url=/,/blog/,/about'
{"warmed":3}
```

Each path is fetched through a **background subrequest** that re-matches the
site's locations (so it must resolve to a `cache_turbo`-enabled location with a
`proxy_pass`), hits the origin once, and stores the result. The admin POST
returns immediately with `{"warmed":N}` (N = subrequests fired); the fetches
finish asynchronously, so a HIT may lag the reply by the origin round-trip. A
warm always re-fetches from origin, even for a URL that is already cached. Up
to 32 paths per call; paths are comma-separated and may be percent-encoded, and
a `?query` suffix on a path is forwarded to the subrequest.

The **stale window** is `cache_turbo_valid × (stale_mult − 1)` (the entry lives
`× stale_mult` total), where `stale_mult` comes from the preset (`4` for the
default `balanced`). So a `balanced` `10s` fresh TTL keeps serving stale for
another `30s` while it refreshes.

### Presets

`cache_turbo_preset` sets the whole tuning bundle at once — handy when you want
"cache hard" or "cache cautiously" without spelling out four knobs. The vocab
matches [wp-redis](https://github.com/eilandert/wp-redis): `conservative`,
`balanced` (default), `aggressive`.

| Knob | `conservative` | `balanced` | `aggressive` |
|---|---|---|---|
| `cache_turbo_valid` (fresh TTL) | `30s` | `60s` | `300s` |
| `cache_turbo_beta` (×1000) | `500` | `1000` | `3000` |
| `cache_turbo_lock_ttl` | `10s` | `5s` | `3s` |
| stale-window multiplier | `×2` | `×4` | `×8` |

```nginx
location / {
    cache_turbo        main;
    cache_turbo_preset aggressive;   # long TTL, wide stale window, eager refresh
    cache_turbo_valid  120s;         # explicit knob overrides the preset's 300s
    proxy_pass http://backend;
}
```

An explicit `cache_turbo_valid` / `_beta` / `_lock_ttl` always beats the preset.
A nearer preset beats a farther one (a `location` preset overrides a `server`
preset). `balanced` equals the historical built-in defaults, so adding presets
changes nothing for configs that don't mention them.

### L2 Redis (shared tier)

```nginx
location / {
    cache_turbo       main;
    cache_turbo_valid 10s;
    cache_turbo_redis 127.0.0.1:6379 prefix=ct: timeout=250ms;
    proxy_pass http://backend;
}
```

L1 (per-node shm) stays the hot path and serves every hit. Redis is touched
only on an L1 **miss** (one synchronous `GET`, then L1 is filled) and on
**store** (asynchronous write-through). So a second node with a cold L1 serves
what the first node cached, without re-hitting the origin. The entry lives in
Redis for the full stale window (`cache_turbo_valid × 4`). The client never
blocks on Redis for a hit.

### Tag-based purge

Tag objects on the way in, then invalidate a whole group with one request —
handy for "drop everything touched by this blog post / product / category"
without enumerating URLs.

```nginx
location / {
    cache_turbo       main;
    cache_turbo_redis 127.0.0.1:6379;
    cache_turbo_tag   $upstream_http_x_cache_tags;   # e.g. "blog post-42"
    proxy_pass        http://backend;
}

location = /_cache {
    cache_turbo_admin main;
    cache_turbo_redis 127.0.0.1:6379;                # so purges hit L2 too
    allow 127.0.0.1; deny all;
}
```

On store, each tag in the expression gets the object's key added to a Redis set
`<prefix>tag:<name>` (with a TTL bounded by the stale window). A
`POST ?tag=<name>` reads that set, drops every member from **both** L1 and L2,
and deletes the set:

```console
$ curl -X POST 'localhost/_cache?tag=post-42'
{"purged":6}
```

Tags live only in Redis, so `cache_turbo_tag` requires `cache_turbo_redis`
(without it a tag purge returns `400`).

### Key normalization

The `$cache_turbo_normalized_args` variable rebuilds the query string so that
requests differing only in argument **order** or carrying tracking junk hash to
one cache slot. It (1) drops denylisted params, (2) sorts the rest, and (3)
re-emits them with a leading `?` (empty string when nothing remains). Compose
your key from it instead of `$is_args$args`:

```nginx
location / {
    cache_turbo      main;
    cache_turbo_key  $scheme$host$uri$cache_turbo_normalized_args;
    proxy_pass       http://backend;
}
```

With this key, `?b=2&a=1` and `?a=1&b=2` are one entry, and `?p=1&utm_source=x`
collapses onto `?p=1`. The variable is orthogonal to keying — it does not touch
`$args`, so application logic still sees the original query string.

Built-in denylist: `utm_*` (prefix), `fbclid`, `gclid`, `msclkid`, `mc_eid`,
`_ga`, `ref`. Add more with `cache_turbo_normalize_strip` (a trailing `*` is a
prefix match); these are *added* to the defaults, never replace them. Drop every
arg with `cache_turbo_normalize_strip_all on`:

```nginx
# strip everything except a curated allow-set you keep via the key itself
cache_turbo_normalize_strip  sid sessionid "tmp_*";   # + the built-in defaults
```

## How it works

```
request ─▶ ACCESS phase ─▶ hash key ─▶ shm lookup
                                          │
              ┌───────────────────────────┼───────────────────────────┐
              ▼                           ▼                            ▼
          fresh hit                  stale hit                       miss
          serve from RAM        serve stale NOW, then:          run origin,
          (X-Cache: HIT)        win the refresh dice?           capture the
                                ├─ yes → fall through to        response in the
                                │        origin, restore        body filter,
                                │        a fresh copy           store to shm
                                └─ no  → just serve stale
                                         (X-Cache: STALE)
```

The read path is lock-free: single-flight is decided by a per-key dice roll
whose probability rises linearly across the stale window, so under concurrency
essentially one reader regenerates and everyone else is served immediately.

## Building

As a dynamic module against your nginx source tree:

```bash
./configure --with-compat --add-dynamic-module=/path/to/nginx-cache-turbo-module
make modules
```

The resulting `objs/ngx_http_cache_turbo_module.so` is loaded with
`load_module`. Packaged builds for Debian/Ubuntu are published via
[deb.myguard.nl](https://deb.myguard.nl).

## Roadmap

- [x] L1 shared-memory cache (rbtree + LRU eviction)
- [x] Stale-while-revalidate + probabilistic single-flight refresh
- [x] Full header fidelity + `X-Cache` debug header
- [x] REST admin endpoint: JSON stats + purge by key / purge all (`cache_turbo_admin`)
- [x] Redis L2 backend (shared/persistent, multi-node) — **native nginx client, no hiredis**
- [x] Tag-based purge (purge by tag, L1 + L2) + L2-aware key/expired purge
- [x] Smart cache-key normalisation — strip tracking params + sort args (`$cache_turbo_normalized_args`); Vary-aware suffix still to come
- [x] `conservative` / `balanced` / `aggressive` tuning presets (`cache_turbo_preset`)
- [x] Cache warming — background prefetch of cold URLs (`POST ?url=`); sitemap walk + TTL-extension rewarmer still to come
- [ ] Live autotune within preset bands (presets are the static version of this)
- [ ] Slashdot protection (widen stale + harden single-flight under load spikes)

## See also

- **[nginx-error-abuse-module](https://github.com/eilandert/nginx-error-abuse-module)** —
  sibling in-NGINX abuse-banning module.
- **wp-redis** — the WordPress object-cache plugin this borrows its SWR /
  autotune algorithms from. cache-turbo is the edge half; wp-redis is the object
  half. Same vocabulary (`conservative`/`balanced`/`aggressive`, `beta`, SWR).
- Packaged for Debian/Ubuntu at **[deb.myguard.nl](https://deb.myguard.nl)**.

## License

MIT — see [LICENSE](LICENSE).
