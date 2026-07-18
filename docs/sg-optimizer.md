# SG Optimizer + cache-turbo

_Last researched: 2026-07-18_

- [The short version](#the-short-version)
- [Cookies: bypass vs key](#cookies-bypass-vs-key)
- [Vhost: page cache only](#vhost-page-cache-only)
- [Object cache (Memcached) — a different thing](#object-cache-memcached--a-different-thing)
- [Gotchas](#gotchas)
- [PHP settings / gotchas](#php-settings--gotchas)
- [See also](#see-also)

## The short version

SG Optimizer (`sg-cachepress`, plugin v7.8.0) is SiteGround's own WordPress
plugin. Its headline caching feature — **Dynamic Caching** — is not a generic
page cache: it hooks into **SiteGround's own managed nginx/proxy layer**.
Confirmed from the plugin source: every purge routes through
`Supercacher::purge_cache_request()`, which returns early (a silent no-op) when
`Helper_Service::is_siteground()` is false; that check tests for
SiteGround-only host markers (`/etc/yum.repos.d/baseos.repo` and `/Z`). Only on
SiteGround does it reach `flush_dynamic_cache()`, which talks to a SiteGround
Unix socket (`/chroot/tmp/site-tools.sock`) that exists nowhere else.
[SiteGround's KB](https://www.siteground.com/kb/siteground-dynamic-caching-configuration/)
describes it the same way; there is no generic nginx integration for it.

**If you're not on SiteGround hosting** (the case this doc is for — a
self-hosted/own-nginx box that still has SG Optimizer installed, usually
because a site was migrated off SiteGround and nobody removed the plugin),
Dynamic Caching has nothing to attach to. Leave it disabled — the toggle may
still render in the admin UI, but it does not function without SiteGround's
proxy behind it.

The plugin does also ship a **file-based cache mode** — confirmed from source
to be host-independent: `File_Cacher` writes a WordPress `advanced-cache.php`
drop-in (plus `WP_CACHE` and an `.htaccess`) and serves static HTML on any
host. This is a
plugin-level page cache, functionally the same category as cache-turbo itself
— **run one or the other, not both**, or you'll cache-double and chase two
purge paths for every content change. Since you're deploying cache-turbo,
disable SG Optimizer's file-based cache and let cache-turbo own full-page
caching:

```nginx
cache_turbo         ct;
cache_turbo_backend wordpress;
```

That's the whole config. Nothing SG-Optimizer-specific to add — see
[`wordpress.md`](wordpress.md) for the full preset (URI skips, `?s=`/`?preview=`
handling, negative caching, etc).

**If you genuinely ARE on SiteGround hosting**: SiteGround manages the
nginx/proxy layer for you, so you're typically not running your own
`nginx.conf` and cache-turbo isn't deployable there in the normal sense. Noted
as an edge case; not elaborated further — that's SiteGround's infrastructure,
not this module's target.

## Cookies: bypass vs key

Nothing extra beyond the `wordpress` preset. Confirmed from source, the
file-based cache's default `$bypass_cookies` set (exposed via the
`sgo_bypass_cookies` filter) is: `wordpress_logged_in_`, `comment_author_`,
`woocommerce_items_in_cart`, `edd_items_in_cart`, and the plugin's own
`wpSGCacheBypass` marker. None of these are SG-Optimizer-*specific* identity
signals; the `wordpress` preset (see
[`wordpress.md`](wordpress.md#cookies-bypass-vs-key)) and, if you run it,
[`woocommerce.md`](woocommerce.md) already bypass the identity/commerce ones.

| Cookie | Treatment | Why |
|---|---|---|
| `wpSGCacheBypass` | **ignore** | plugin's own cache-bypass marker (confirmed in the default `$bypass_cookies` list), not a visitor identity signal |

No table row needs adding to your vhost. If SG Optimizer's file-based cache
is disabled (recommended, see above), this cookie won't even appear in
production traffic.

## Vhost: page cache only

Same syntax as the WordPress preset — nothing SG-Optimizer-specific:

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    server {
        listen 443 ssl http2;
        server_name example.com;
        root /var/www/wordpress;
        index index.php;

        location / {
            try_files $uri $uri/ /index.php?$args;
        }

        location ~ \.php$ {
            cache_turbo         ct;
            cache_turbo_backend wordpress;
            cache_turbo_valid   60s;
            cache_turbo_preset  balanced;

            include              fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_pass  unix:/run/php/php-fpm.sock;
        }

        location = /_cache {
            cache_turbo_admin on;
            allow 127.0.0.1;
            deny  all;
        }
    }
}
```

## Object cache (Memcached) — a different thing

SG Optimizer's Memcached integration is WordPress's internal **object
cache** (query/option/transient data for every request, including logged-in
ones) — the same category noted in
[`wordpress.md`](wordpress.md#wordpresss-own-object-cache--a-different-thing)
and [`xenforo.md`](xenforo.md#xenforos-own-object-cache-redis--a-different-thing).
It is orthogonal to page caching: cache-turbo caches rendered HTML for
anonymous visitors, the object cache speeds up the origin for everyone else.
**Note:** confirmed from source, SG Optimizer's Memcached is bound to a
hardcoded SiteGround per-user socket (`/home/.tmp/memcached.sock`) — its
connection test bails if that socket is absent, and the `object-cache.php`
drop-in renames itself to `object-cache-socket-missing.php` when it can't
connect. So off-SiteGround the plugin's *own* Memcached integration won't come
up; run a separate object-cache plugin (Redis Object Cache, or a Memcached
drop-in pointed at your own server) instead. Either way, no conflict with
cache-turbo — page cache and object cache sit in different layers.

## Gotchas

- **Migrated sites keep the plugin out of inertia.** A WP install moved off
  SiteGround commonly still has SG Optimizer active. Its Dynamic Caching
  toggle may still show as available in the admin UI — it will do nothing on
  non-SiteGround infrastructure, per the SiteGround-proxy dependency above.
  Safe to leave off; uninstalling the plugin entirely once migrated is also
  fine and avoids any confusion for the next person who opens the settings
  page.
- **Don't run SG Optimizer's file-based cache alongside cache-turbo.** Two
  page caches means double storage, double staleness windows, and two purge
  paths to keep in sync on every publish. Disable the plugin's file cache;
  let cache-turbo be the only page cache.
- **Other SG Optimizer features are unaffected.** Image optimization,
  minify/combine, lazy load, and the various Core Web Vitals tweaks are
  independent of caching — keep using them as normal.

## PHP settings / gotchas

SG-Optimizer-specific PHP concerns off SiteGround (cache-turbo runs in nginx and
is unaffected by all of these):

- **Dynamic Caching purge is a silent no-op off-platform.** As shown above, the
  purge path returns `true` without contacting anything when `is_siteground()`
  is false — no socket call, no error. So don't wire any deploy step to it and
  expect a flush; use cache-turbo's own admin purge (`cache_turbo_admin`)
  instead.
- **Its Memcached object cache needs the `memcached` PHP extension AND a live
  memcached** — and, per source, it only talks to SiteGround's hardcoded
  `/home/.tmp/memcached.sock`, so off-platform it simply won't connect. This is
  the plugin's origin-side object cache, unrelated to cache-turbo's L2 disk
  tier. Use a general object-cache plugin instead if you want one.
- **Opcache still matters.** SG Optimizer does no bytecode caching of its own;
  the plugin's PHP (and all of WordPress) benefits from a properly sized
  `opcache` — cache-turbo serving anonymous hits from nginx just means opcache
  pressure comes mostly from logged-in/admin traffic.
- **Combine/Minify CSS-JS costs PHP CPU off SiteGround.** On SiteGround the
  minifier shells out to a compiled `minify` binary; off-platform it falls back
  to an in-process PHP minifier library (`minify_scripts_lib`), so the
  frontend-optimization features add real PHP-FPM load on first render of each
  asset. Fine to use, just size PHP-FPM workers accordingly.

## See also

- [`wordpress.md`](wordpress.md) — the WordPress preset this doc builds on
- [`woocommerce.md`](woocommerce.md) — if the site also runs WooCommerce
- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [README — The cache key](../README.md#the-cache-key)
