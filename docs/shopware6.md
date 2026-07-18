# Shopware 6 + cache-turbo

_Last researched: 2026-07-18_

Caching a Shopware 6 (6.4–6.8) storefront. **Same engine as [magento](magento.md)**
— Shopware ships its own Varnish VCL and value-keys the one cookie that VCL keys
on, exactly the way upstream does. This preset **is** that VCL, translated, with
no deviation.

- [The short version](#the-short-version)
- [`sw-cache-hash`: value-keyed, never bypassed](#sw-cache-hash-value-keyed-never-bypassed)
- [Cookies that must NOT bypass](#cookies-that-must-not-bypass)
- [Vhost](#vhost)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend shopware6;    # implies cache_turbo_cache_control honor
```

That's it for a correct, safe config — the vary cookie is handled natively, no
`map` required.

## `sw-cache-hash`: value-keyed, never bypassed

| Check | Values |
|---|---|
| URI prefixes | `/account`, `/checkout`, `/admin`, `/api`, `/store-api` |
| Query args | — |
| Key cookies (value folded into cache key) | `sw-cache-hash` |

**Matched cookie: exact name `sw-cache-hash`.** It is a **segment fingerprint**,
not an identity, and it is folded into the cache key, not used as a bypass.
`CacheHeadersService::buildCacheHash()` (`CacheHeadersService.php:104`) folds
`{rule_ids, version_id, currency_id, tax_state, logged_in_state}` into the hash,
where `logged_in_state` is literally the string `'logged-in'` or `'not-logged-in'`
— the login bit lives *inside* the hash **value**, not in whether the cookie is
present. Shopware's own Varnish config does the identical thing:

```vcl
hash_data("+context=" + cookie.get("sw-cache-hash"));
```

(`shopware/varnish-shopware`, `default.vcl`)

**Why a bypass would be wrong.** `isCacheHashRequired()`
(`CacheHeadersService.php:125`) returns true for a **logged-in customer OR a
guest with a filled cart OR a guest on a non-default currency**. Bypassing on
cookie presence would send cart-holding *guests* and non-default-currency
*guests* to the origin for nothing — their private data is never in the cached
HTML; Shopware fetches the cart client-side, same as Magento's private-content
sections. This is exactly the mistake that was removed from the `magento`
preset in PR #28, and it would be the same mistake here on day one.

**Lazy, aggressively so.** When the hash is not required, `applyCacheHash()`
(`CacheHeadersService.php:62`) does not merely omit the cookie — it **deletes a
stale one** (`removeCookie` + `clearCookie`). A default anonymous visitor is
therefore guaranteed cookieless, so the anonymous bucket is the common case and
hit rate is good.

**`sw-states` is deliberately NOT matched — matching it would be a leak on a
current shop.** It was **removed in 6.8**
(`UPGRADE-6.8.md`: *"Removed `sw-states` and `sw-currency` cache cookie handling
... The complete caching behaviour is now controlled by the `sw-cache-hash`
cookie"*). `HttpCacheKeyGenerator::SYSTEM_STATE_COOKIE` carries an `@deprecated
tag:v6.8.0`, and `CacheResponseSubscriber` gates that whole code path off under
`Feature::isActive('v6.8.0.0')`. A preset keyed on `sw-states` alone would
silently stop firing the moment a shop upgrades — the classic "matcher stops
matching ⇒ logged-in pages get cached" failure. `sw-cache-hash` is the one
cookie that spans 6.4 through 6.8 unbroken.

> **⚠️ Do not write `$cookie_sw_cache_hash`.** It looks right and it **silently
> never matches**. `HttpCacheKeyGenerator::CONTEXT_CACHE_COOKIE = 'sw-cache-hash'`
> (`:27`) is hyphenated, and nginx does not translate `-` to `_` for cookie names
> (unlike request headers, where `$http_x_forwarded_for` works). This is exactly
> why the preset parses the raw `Cookie:` header itself instead of relying on
> nginx's `$cookie_` variables — no `map` workaround is needed, or possible to
> get right by hand. Same note as [magento](magento.md#x-magento-vary-value-keyed-not-bypassed).

## Cookies that must NOT bypass

| Cookie | Why it is not a bypass |
|---|---|
| `sw-states` | Removed in 6.8 (see above) — matching it stops firing silently on an upgraded shop. `sw-cache-hash` already carries everything it used to. |
| `sw-currency` | Same removal, same reason — folded into `sw-cache-hash` now. |
| `sw-context-token` | Set for **every** visitor, guest included — it identifies the sales-channel context, not a login. Bypassing on it zeroes your storefront hit rate. It is, however, why `/store-api` is bypassed by URI below (see [Gotchas](#gotchas)). |

## Vhost

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 512m;

    upstream fastcgi_backend { server unix:/run/php/php-fpm.sock; }

    server {
        listen 443 ssl http2;
        server_name shop.example.com;
        root /var/www/shopware/public;

        location / {
            try_files $uri /index.php$is_args$args;
        }

        location ~ ^/index\.php$ {
            cache_turbo               ct;
            cache_turbo_backend       shopware6;  # implies cache_control honor
                                                    # and value-keys sw-cache-hash

            cache_turbo_key           $scheme$host$uri$is_args$args;
            cache_turbo_valid         300s;
            cache_turbo_valid         404 410 1m;
            cache_turbo_preset        balanced;

            fastcgi_pass   fastcgi_backend;
            fastcgi_param  SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
            fastcgi_param  DOCUMENT_ROOT $realpath_root;
            include        fastcgi_params;
        }

        # Theme + media assets are served straight off disk.
        location ~* ^/(media|theme|bundles)/ {
            cache_turbo off;
            expires max;
            access_log off;
        }

        location = /_cache {
            cache_turbo_admin on;
            allow 127.0.0.1;
            deny  all;
        }
    }
}
```

## Checking it works

```nginx
add_header X-Cache-Turbo $cache_turbo_status always;
```

```bash
# anonymous storefront page: MISS then HIT.
curl -s -o /dev/null -D- https://shop.example.com/some-category | grep -i x-cache-turbo
curl -s -o /dev/null -D- https://shop.example.com/some-category | grep -i x-cache-turbo   # HIT

# account / checkout / admin / api: BYPASS
curl -s -o /dev/null -D- https://shop.example.com/account            | grep -i x-cache-turbo
curl -s -o /dev/null -D- https://shop.example.com/checkout/confirm    | grep -i x-cache-turbo

# THE HIT-RATE CHECK. A default anonymous visitor gets NO sw-cache-hash cookie
# (it is actively deleted if stale) -- must still be a HIT.
curl -s -o /dev/null -D- https://shop.example.com/some-category | grep -i x-cache-turbo   # HIT, no cookie needed

# THE SEGMENTATION CHECK. Two different hash values must land in two different
# entries -- neither a HIT off the other's warm-up.
curl -s -o /dev/null -D- -H 'Cookie: sw-cache-hash=9f2a4c1e' \
     https://shop.example.com/some-category | grep -i x-cache-turbo   # MISS (first time)
curl -s -o /dev/null -D- -H 'Cookie: sw-cache-hash=9f2a4c1e' \
     https://shop.example.com/some-category | grep -i x-cache-turbo   # HIT (own segment)
curl -s -o /dev/null -D- -H 'Cookie: sw-cache-hash=deadbeef' \
     https://shop.example.com/some-category | grep -i x-cache-turbo   # MISS (different segment)
```

Run both checks before you go live. Note the module never stores `HEAD`
responses, so a `curl -sI` HEAD request can **never** show a `HIT` here — the
recipes above are deliberately GET (`-s -o /dev/null -D-`), not `-sI`.

## Gotchas

- **`/store-api` is bypassed, not cached, because it is context-sensitive per
  `sw-context-token`** — a per-visitor sales-channel context that must never be
  shared between requests. It is not covered by the `sw-cache-hash` mechanism
  at all; it is a separate API surface.
- **`/admin` here means Shopware's own administration SPA path**, distinct from
  the storefront. Unlike Magento, Shopware does not randomise this path.
- **Prefer not to set `cache_turbo_cache_control ignore`.** It overrides the
  `honor` that `cache_turbo_backend` implies, so you stop obeying the `no-store`
  Shopware already sends on its private pages, and the URI rules become your only
  defence there. It does **not**, however, weaken the vary-transition race: that
  is guarded by the unconditional "never store a `Set-Cookie` response" floor,
  which is checked *before* and *outside* the `Cache-Control` handling and so
  survives `ignore` (see [magento's writeup](magento.md#the-transition-race)).
  That floor is what stops a guest's first cart-add — the response that *sets*
  `sw-cache-hash` — from poisoning the anonymous bucket.
- **A wide vary key range can grow the cache.** Every distinct `sw-cache-hash`
  value is its own full set of cache entries — logged-in customer groups,
  non-default currencies, active promotion rule sets each fork the key space.
  Size your zone and TTLs with that multiplication in mind, exactly as with
  `magento`.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached, regardless of preset.

## PHP settings / gotchas

Shopware 6 is Symfony-based and runs on PHP-FPM; the items below are the ones
that specifically bite a Shopware storefront sitting behind `cache-turbo`.
Generic FPM pool tuning is out of scope.

- **`sw-cache-hash` is the cache-vary key — bank this.** The whole preset rests
  on folding that one cookie's *value* into the cache key (see above). Since 6.8
  it is the **only** cache cookie: it carries logged-in state, tax state,
  currency, and the matched cache-rule set, and `sw-states` / `sw-currency` are
  gone. Do not bolt on a `$cookie_`-based `map` for login or currency state — it
  already lives inside `sw-cache-hash`, and (on <6.8) `sw-states=logged-in` was
  only ever a redundant tag for the same bit.

- **Shopware — not cache-turbo — owns invalidation.** Shopware's built-in Symfony
  reverse-proxy cache layer emits `BAN` invalidation requests (config key
  `shopware.http_cache.reverse_proxy`, `ban_method: "BAN"`, optionally
  `use_varnish_xkey`) to a Varnish/Fastly front when an entity changes, sharing
  the same tags as its object cache. cache-turbo has no BAN endpoint, so it
  relies on TTL expiry (`cache_turbo_valid`), not event-driven purge — keep TTLs
  modest and leave Shopware's tag-based invalidation authoritative. If you need
  event-driven storefront purges, that is Varnish/Fastly territory, run in front
  of (or instead of) this preset, not a job this preset does.

- **`SHOPWARE_HTTP_CACHE_ENABLED=1`** in `.env` is what turns on Shopware's HTTP
  cache and the `Cache-Control` / `no-store` headers this preset honors. With it
  off, Shopware stops emitting those headers and the URI rules
  (`/account`, `/checkout`, …) become your only defence on private pages.

- **opcache — size it for Symfony's class count.** Set
  `opcache.memory_consumption` high (256–512 MB) and `opcache.max_accelerated_files`
  to 20000+; Shopware blows past the 10000 default and silently thrashes opcache
  otherwise. On persistent FPM, point `opcache.preload` at
  `<project>/var/cache/opcache-preload.php` (the Symfony preload file Shopware
  generates) with `opcache.preload_user` set to the FPM user, and in production
  run `opcache.validate_timestamps=0` (flush opcache on deploy).

- **`memory_limit` on the CLI is separate from the pool.** `bin/console`
  commands — `theme:compile`, `dal:refresh:index`, `cache:warmup` — routinely
  need 512 MB+ and read the CLI `php.ini`, not the FPM pool. An OOM there can
  leave a half-compiled theme or a stale index that the cache then happily serves.

- **`realpath_cache_size`.** Symfony/Shopware stat a very large file tree; raise
  `realpath_cache_size` to 4096K+ and `realpath_cache_ttl` to ~600s, or the
  filesystem lookups surface as latency on every MISS.

- **`max_execution_time` for indexers and workers.** Message-queue workers
  (`messenger:consume`) and the DAL indexers are long-running — run them from CLI
  (no wall clock) or with an explicit `--time-limit`, never bounded by the web
  pool's `max_execution_time`. A worker killed mid-run backs up the queue, so
  Shopware's invalidations never reach the cache and stale pages linger to TTL.

## See also

- [`docs/magento.md`](magento.md) — the same value-keyed-cookie shape, worked in detail
- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/README.md`](README.md) — all presets
