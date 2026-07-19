# NitroPack + cache-turbo

_Last researched: 2026-07-18_

NitroPack is architecturally different from every other plugin in this doc set —
this page exists to explain that difference before it costs you a debugging
afternoon.

- [The short version](#the-short-version)
- [Why NitroPack isn't "stacked" like the others](#why-nitropack-isnt-stacked-like-the-others)
- [Headers](#headers)
- [Vhost: origin-side cache-turbo behind NitroPack](#vhost-origin-side-cache-turbo-behind-nitropack)
- [Real IP / X-Forwarded-For](#real-ip--x-forwarded-for)
- [Gotchas](#gotchas)
- [PHP settings / gotchas](#php-settings--gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend wordpress;
```

Run cache-turbo on the origin exactly as you would without NitroPack. Do **not**
try to build a NitroPack-specific preset — there's no request-side signal to key
or bypass on beyond the stock `wordpress` cookie rules, and the interesting part
of this integration is architectural, not directive-level.

## Why NitroPack isn't "stacked" like the others

Every other plugin in this doc set (WordPress core, WooCommerce, Joomla, XenForo)
caches **locally** — a plugin writes rendered HTML to disk or an object-cache
backend that lives on (or next to) your origin server, and cache-turbo sits in
front of that same origin, at the same layer, genuinely competing/cooperating
for the same requests.

**NitroPack is not that.** It's a reverse-proxy/CDN SaaS: the WordPress plugin is
a *connector*, not the cache itself. Confirmed from NitroPack's own docs
([What does the NitroPack plugin do for WordPress sites?](https://nitropack.io/blog/what-does-nitropack-do-wordpress/),
[server requirements](https://support.nitropack.io/en/articles/8390446-server-requirements))
and cross-checked against the connector plugin source (wordpress.org slug
`nitropack`, Stable tag **1.19.8**, source read 2026-07-18):

- The actual caching, image optimization, and minification happen on
  **NitroPack's own servers** — "on its own servers, which preserves your
  hosting resources."
- NitroPack **relies on DNS-based detection**: the standard/default deployment
  is your domain's DNS pointing at NitroPack's own IPs (or, if you also run
  Cloudflare or another proxy in front, an extra integration step is required).
  In other words: **NitroPack sits in front of your entire server**, not behind
  it — same position a CDN like Cloudflare or Fastly occupies.
- It ships a built-in CDN "powered by Cloudflare" for the edge network itself.

One nuance the marketing framing hides, confirmed in the bundled SDK
(`nitropack-sdk/bootstrap.php`, `functions.php`): the connector also installs a
WordPress `advanced-cache.php` drop-in (`AdvancedCache::install_advanced_cache()`,
`WP_CACHE` set to `true`) and, in deployments where DNS is *not* pointed at
NitroPack's edge, it serves NitroPack-optimized HTML from a **local page cache on
your origin's own disk** — `hasLocalCache()` → `pageCache->readfile(); exit;`,
emitting `X-Nitro-Cache: HIT`/`STALE` and a short-lived `nitroCache` cookie
before WordPress fully boots. So the "origin never sees the request" statement
below is specific to the **DNS/edge-proxy** deployment. In the connector-only
(no-DNS) deployment NitroPack does run at the origin, at the same layer as
cache-turbo — but it serves from PHP via the drop-in, so it still sits *behind*
cache-turbo's `\.php$` handler, not in front of it.

The practical consequence: on a cache **HIT**, NitroPack's edge answers the
request and **your origin nginx never sees it at all** — cache-turbo has nothing
to do with that transaction. Only a NitroPack **MISS or bypass** is proxied back
to your origin, and that's the only traffic cache-turbo ever gets a chance to
touch. This is not "stacking two page caches at the same layer" the way
WordPress-core-plugin-A + cache-turbo would be — it's two caches at two
different layers in the request path, with NitroPack normally absorbing most of
the traffic before cache-turbo is even reached.

**Is cache-turbo redundant once NitroPack is in front?** No — it isn't fully
redundant, for the same reason running any origin-side cache behind a CDN isn't
redundant:

- NitroPack correctly bypasses logged-in/dynamic requests straight to origin
  (admin users, cart/checkout, form submissions) — that traffic gets nothing
  from NitroPack's cache and previously got nothing from origin either;
  cache-turbo can't help authenticated traffic any more than NitroPack can (both
  correctly bypass it), but it *can* help the **anonymous, cacheable** slice of
  what reaches origin.
- Crawlers, uncached long-tail URLs, NitroPack cache warm-up requests, and
  origin health checks all reach your box directly. If cache-turbo isn't
  running there, every one of those is a full PHP render; if it is, the second
  and subsequent hits on the same URL are served from shm/Redis instead.
- If NitroPack's edge cache is ever purged, disabled, over quota, or the visitor
  arrives via an integration path NitroPack doesn't optimize (some query
  strings, some UA classes), origin absorbs full traffic — you want a warm
  cache-turbo zone there, not a cold PHP stack.

## Headers

Searched NitroPack's public docs and support articles for a distinguishing
request header sent **to origin** that cache-turbo's presets should recognize.
Found only **response-side** headers NitroPack's edge adds to what it serves to
the browser — nothing sent upstream to origin that would be useful in an nginx
`map`/bypass rule:

| Header | Direction | Meaning |
|---|---|---|
| `X-Nitro-Cache: HIT` | edge → browser (or origin drop-in → browser in connector-only mode) | served from NitroPack's cache — the edge in DNS mode, or the origin `advanced-cache.php` drop-in (`HIT`/`MISS`/`STALE`) in connector-only mode |
| `X-Nitro-Header: Disabled` | response, per NitroPack docs | signals NitroPack skipped optimizing that response |
| `X-Nitro-Expires` | response | optimization-cache expiry NitroPack uses internally |

None of these appear on the request NitroPack forwards to your origin. **No
NitroPack-specific `cache_turbo_bypass`/key rule is needed** beyond the stock
`wordpress` preset — unverified/community-reported that this remains true across
all NitroPack integration modes (some hosting-partner "server-level"
integrations may differ; nothing in NitroPack's public docs describes an
origin-bound identification header, and none showed up in the sources checked
for this page).

## Vhost: origin-side cache-turbo behind NitroPack

Same as [`wordpress.md`](wordpress.md) — no NitroPack-specific directives, only
the `real_ip` block added:

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    # $cookie_NAME is an EXACT-name lookup, and WordPress suffixes its cookie
    # names with an md5 of the site URL. $cookie_wordpress_logged_in_ is
    # therefore ALWAYS empty -- match the prefix out of the raw Cookie header
    # instead.
    map $http_cookie $wp_logged_in {
        default                                        0;
        "~*(^|;\s*)wordpress_logged_in_[0-9a-f]{32}="   1;
    }

    server {
        listen 443 ssl http2;
        server_name example.com;
        root /var/www/wordpress;
        index index.php;

        # See "Real IP" below — traffic now arrives via NitroPack's proxy,
        # not the visitor directly. NitroPack does not publish a fixed,
        # citable IP-range list as of this writing -- get current ranges
        # from NitroPack support/docs first, then uncomment with THOSE
        # ranges. Never use 0.0.0.0/0: it trusts X-Forwarded-For from any
        # client, letting a direct caller spoof the real IP.
        # set_real_ip_from  <NitroPack-published-CIDR>;
        # real_ip_header    X-Forwarded-For;
        # real_ip_recursive on;

        location / {
            try_files $uri $uri/ /index.php?$args;
        }

        location ~ \.php$ {
            cache_turbo               ct;
            cache_turbo_backend       wordpress;   # same preset as a bare WP site

            cache_turbo_valid         60s;
            cache_turbo_valid         404 410 1m;
            cache_turbo_preset        balanced;

            cache_turbo_no_store      $wp_logged_in;

            include                   fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_pass  unix:/run/php/php-fpm.sock;
        }

        location ~* \.(css|js|png|jpe?g|gif|webp|svg|woff2?)$ {
            cache_turbo off;
            expires 30d;
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

## Real IP / X-Forwarded-For

With NitroPack sitting in front of your origin (DNS-level, the standard mode —
see above), every request nginx sees arrives from **NitroPack's proxy IPs**, not
the visitor's real IP. This matters for:

- **Access logs** — every log line shows a NitroPack IP unless corrected.
- **Any IP-based logic** in your vhost (rate limiting, geo rules, `deny`/`allow`
  lists) — it will act on the proxy's IP, not the visitor's.
- cache-turbo itself doesn't key or bypass on client IP by default in the
  `wordpress` preset, so this is not a cache-correctness issue for cache-turbo —
  but it is exactly the same "behind a CDN" gotcha you'd handle for Cloudflare
  or Fastly, using nginx's standard `ngx_http_realip_module`
  (`set_real_ip_from` + `real_ip_header X-Forwarded-For`).

**Could not find a published, current list of NitroPack's proxy/edge IP
ranges** in the sources checked for this page — NitroPack's help center
references an article titled "How to Allowlist NitroPack's IP Addresses" (seen
only as a cross-reference, content not confirmed here). **Consult NitroPack's
own published IP-range docs directly before writing `set_real_ip_from` — do not
invent or guess ranges.** That's why the `real_ip` block above ships commented
out rather than with a wildcard: `set_real_ip_from 0.0.0.0/0` would trust the
`X-Forwarded-For` header from literally any client and must never ship as-is.

## Gotchas

> **Subdirectory installs.** This preset's URI rules are root-relative literals
> matched from byte 0 of `r->uri`, so an install mounted under a subdirectory
> (`/shop/`, `/forum/`, …) matches **none** of them — the admin surface
> included. Declare the mount with `cache_turbo_backend_prefix /forum/;` and the
> preset URI tier is compared against the rebased path. Scoping the nginx
> `location` does **not** substitute: it routes requests, it does not rewrite
> `r->uri`. See [frameworks.md](frameworks.md).

- **Purging cache-turbo's origin cache is necessary but not sufficient.** With
  NitroPack's edge in front, a HIT at NitroPack never reaches your origin — so
  purging cache-turbo's zone (`curl -X POST '.../_cache?key=...'`) does nothing
  for a visitor NitroPack is still serving from its own edge cache. **You need
  both purges**:
  1. NitroPack's own purge (dashboard "Cache" tab, or its Cloud API) — clears
     the edge, the layer visitors actually hit. The connector fires this itself
     on WordPress content-change hooks: verified in the bundled SDK, it POSTs to
     NitroPack's Cloud API `cache/purge/<siteId>` endpoint (`Api\Cache::purge()`),
     and NitroPack also drives cache-clear webhooks back to the connector.
  2. cache-turbo's origin purge (`/_cache?key=...` or `?all=1`) — clears the
     origin-side cache so the *next* NitroPack MISS/bypass that reaches your
     box gets fresh content instead of a stale origin render.
  Order: purge NitroPack's edge first is the common pattern (it's the layer
  users see), but if content changed on origin (a plugin/theme edit, not just a
  post publish), purge origin first so NitroPack's next fetch-on-miss pulls
  fresh HTML — unverified/community-reported which order NitroPack itself
  recommends; nothing pinned this down authoritatively in the sources checked,
  so treat "purge both, promptly, in either order" as the safe baseline rather
  than relying on an implied sequencing guarantee.
- **Don't build a NitroPack preset.** There's no request-side signal distinct
  from stock WordPress to key or bypass on (see Headers above) — the
  `wordpress` preset is already correct for the traffic that reaches origin.
- **Reverse-proxy integration mode is real, and confirmed in the SDK.** The
  bundled SDK ships `Integrations\ReverseProxy` with `Varnish` and `Nginx`
  subclasses, and `NitroPack::purgeProxyCache()` fires them on every purge:
  it issues a configurable `PURGE`-method request (default `PURGE`) to the
  origin proxy server list from `config->CacheIntegrations->Varnish`. So on a
  purge NitroPack can clear an origin-side reverse-proxy/Varnish/nginx cache
  *as well as* its edge. The mechanism exists and is account-config-gated —
  which deployments enable it (and against which origin proxy) is account/host
  specific, so verify your NitroPack configuration rather than assuming. This
  is NitroPack purging an origin *proxy* cache; it is unrelated to cache-turbo,
  whose zone you still purge via its own `/_cache` admin endpoint. If you're on
  that mode, the purge-ordering and real-IP notes above still apply.
- **Two caches, two dashboards.** Don't debug a "stale content" report by only
  checking cache-turbo's `$cache_turbo_status` header — if NitroPack's edge is
  serving the HIT, that header from origin never shows up in the response the
  visitor got at all.

## PHP settings / gotchas

NitroPack-specific PHP/origin concerns — general PHP-FPM and opcache tuning lives
in [`wordpress.md`](wordpress.md); only what NitroPack changes is repeated here.

- **Fix the real client IP before anything at origin reads it.** In DNS/edge
  mode every request reaches your box from a NitroPack edge IP, with the real
  visitor in `X-Forwarded-For`. Two independent consumers care:
  - **nginx** — `$remote_addr`, access logs, rate limiting, and `deny`/`allow`
    all see the edge IP until you correct them with the standard
    `ngx_http_realip_module` (`set_real_ip_from` + `real_ip_header X-Forwarded-For`
    + `real_ip_recursive on`, as in the vhost above). Use NitroPack's published
    edge ranges — never the `0.0.0.0/0` placeholder.
  - **PHP** — the connector reads the client IP itself via `getRemoteAddr()`,
    whose order is `HTTP_X_FORWARDED_FOR` → `HTTP_CF_CONNECTING_IP` →
    `REMOTE_ADDR` (verified in the SDK). So NitroPack trusts `X-Forwarded-For`
    unconditionally at the PHP layer; if any other plugin or your own code reads
    `$_SERVER['REMOTE_ADDR']` for geo/security/analytics it will still see the
    edge IP unless nginx's `real_ip` rewrite has already fixed it. Set `real_ip`
    once at nginx and both layers agree.
- **Dual-purge is a PHP-side event, not just a dashboard button.** Publishing or
  editing content fires the connector's WordPress hooks, which make a blocking
  outbound HTTPS call to NitroPack's Cloud API (`cache/purge/<siteId>`) inside
  the request that saved the post. That purges the edge; it does **not** purge
  cache-turbo's origin zone — wire cache-turbo's `/_cache` purge into the same
  content-change path (or accept its short `cache_turbo_valid` TTL) so the next
  origin MISS renders fresh.
- **Cache warm-up / miss traffic is outbound-API-heavy PHP.** On a local miss the
  connector calls NitroPack's API (`cache/get`, `hasRemoteCache`) — a real
  outbound HTTPS round-trip from PHP — and warmup, beacon, and Lighthouse/GTmetrix/
  Pingdom probe requests each trigger their own API ping. Every one of those is a
  full PHP execution plus a network wait. This is exactly the slice cache-turbo
  shields: once a cacheable anonymous URL is warm in the cache-turbo zone, repeat
  hits are served from shm/Redis and never re-enter PHP or re-fire the NitroPack
  API call. Keep PHP-FPM `pm.max_children` sized for the outbound-wait concurrency
  these calls add, since a blocked-on-NitroPack worker is still an occupied worker.
- **Opcache must cover the connector, not just your theme.** The connector bundles
  a large SDK (200+ PHP files under `nitropack-sdk/`) plus an `advanced-cache.php`
  drop-in that runs on every uncached request. Give opcache enough
  `opcache.memory_consumption` and `opcache.max_accelerated_files` headroom to
  hold it, and after a plugin update invalidate opcache so the drop-in and SDK
  are recompiled rather than served stale.

## See also

- [`wordpress.md`](wordpress.md) — the WordPress preset baseline this page
  builds on (URI/cookie rules are unchanged under NitroPack)
- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [README — The cache key](../README.md#the-cache-key)
- [`docs/README.md`](README.md) — all presets
