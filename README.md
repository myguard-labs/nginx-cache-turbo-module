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

> **Status: v1 (alpha).** L1 shared-memory cache with SWR + probabilistic
> refresh works and is smoke-tested. Redis L2 (shared/multi-node), tag-based
> purge, a REST admin API, smart key normalisation, cache warming, and the
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
| `cache_turbo_valid TIME` | `server`, `location` | `60s` | Fresh TTL. After this the entry is *stale* (still served). |
| `cache_turbo_beta N` | `server`, `location` | `1000` | SWR refresh aggressiveness, fixed-point ×1000 (1000 = 1.0). Higher → refresh earlier/more often. |
| `cache_turbo_max_size SIZE` | `server`, `location` | `1m` | Largest single response to cache. |

The **stale window** is `cache_turbo_valid × 3` (the entry lives `× 4` total),
so a `10s` fresh TTL keeps serving stale for another `30s` while it refreshes.

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
- [ ] Redis L2 backend (shared/persistent, multi-node) via async hiredis
- [ ] Tag-based purge + REST admin API (`/_cache/purge`, `/_cache/stats`)
- [ ] Smart cache-key normalisation (strip tracking params, sort args, Vary-aware)
- [ ] Cache (re)warming — sitemap walk + TTL-extension
- [ ] `conservative` / `balanced` / `aggressive` autotune presets
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
