# Hummingbird + cache-turbo

_Last researched: 2026-07-18_

Interop notes for **Hummingbird** (WPMU DEV's `hummingbird-performance`,
v3.19.0, 100k+ installs) on a site fronted by cache-turbo. This is **not** a new
backend preset — Hummingbird runs on stock WordPress with stock WP auth
cookies, so the existing `wordpress` preset already covers it. This page is
about which of Hummingbird's *own* modules to turn off.

- [The short version](#the-short-version)
- [How Hummingbird's page cache works](#how-hummingbirds-page-cache-works)
- [Cookies: bypass vs key](#cookies-bypass-vs-key)
- [Vhost: page cache only](#vhost-page-cache-only)
- [Multisite note](#multisite-note)
- [Purging on publish](#purging-on-publish)
- [Gotchas](#gotchas)
- [PHP settings / gotchas](#php-settings--gotchas)
- [See also](#see-also)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend wordpress;
```

Same preset as stock WordPress — see [`wordpress.md`](wordpress.md) for the
full baseline (URI skips, cookie bypasses, key). The only Hummingbird-specific
action is in the plugin's own settings, not in nginx:

- **Turn OFF** Hummingbird's **Page Caching** module — cache-turbo owns the
  page cache now, and running both means every request path writes/reads two
  independent full-page caches (see [Gotchas](#gotchas)).
- **Leave ON** Asset Optimization (minify/combine JS+CSS), Gzip, Browser
  Caching (headers), and CDN. These operate on the *response body and
  headers* PHP produces, not on whether the request reaches PHP at all —
  orthogonal to cache-turbo and complementary to it. A cache-turbo cache HIT
  serves the already-minified, already-gzip'd, CDN-rewritten HTML that PHP
  produced on the MISS that populated it.

## How Hummingbird's page cache works

Hummingbird's Page Caching module is disk-based and PHP-driven, in the same
family as WP Super Cache / WP Fastest Cache: it writes rendered HTML under
`wp-content/wphb-cache/cache/` and decides on each request whether to serve
the cached file or let WordPress render fresh. The mechanism is the **standard
WordPress `advanced-cache.php` drop-in** — exactly like Super Cache/W3TC, not
a database rewrite rule. On activation the plugin copies its
`core/advanced-cache.php` to `wp-content/advanced-cache.php` and adds
`define( 'WP_CACHE', true );` to `wp-config.php` (source:
`core/modules/class-page-cache.php`, the `WP_CACHE`/`advanced-cache.php`
handling around lines 170–382). WordPress core includes that drop-in very
early in `wp-settings.php` when `WP_CACHE` is truthy, and the drop-in's lookup
runs before the main WP load — but it is still a *PHP-layer* cache: every hit
invokes the PHP interpreter to run that lookup, unlike cache-turbo's
nginx-layer HIT which never reaches PHP-FPM at all.

Its cache-key logic checks logged-in state via WP core's
`is_user_logged_in()` (confirmed:
`core/modules/class-page-cache.php:877-878`), falling back to a
`wordpress_logged_in_*` cookie scan when that function is not yet available in
the drop-in. Whether logged-in users are cached at all is a settings toggle
(`cache_logged_in`, off by default).

## Cookies: bypass vs key

Nothing beyond the stock WordPress preset. Hummingbird does **not** set a
session/auth cookie of its own — a grep of the source turns up no `setcookie`
for a `wphb_*` name. Its Page Caching module *does* reference `wphb_cache_*` as
one of the cookie prefixes it folds into its **own** page-cache key (source:
`core/modules/class-page-cache.php:751`, the
`^wp-postpass_|^comment_author_|^wordpress_logged_in_|^wphb_cache_` match), but
that is a vary/bypass trigger for a cookie some other component would have to
set — the plugin never mints one in core, so on a stock install there is no
such cookie to reach cache-turbo. Identity is decided by WP core's
`wordpress_logged_in_*` exactly like every other plugin covered in
[`wordpress.md`](wordpress.md). Nothing to add to `cache_turbo_key` or an extra
bypass rule.

| Cookie | Treatment | Why |
|---|---|---|
| `wordpress_logged_in_*` | **bypass** (stock preset) | authenticated user |
| `wp-postpass_*` | **bypass** (stock preset) | password-protected post reader |
| `comment_author_*` | **bypass** (stock preset) | WP personalises the comment form for them |

No Hummingbird-specific row. If a future Hummingbird release adds a cookie of
its own (e.g. an A/B or CDN-edge cookie), remember `Set-Cookie` responses are
never stored by cache-turbo regardless of preset — that floor covers it even
before anyone updates this doc.

## Vhost: page cache only

Identical to the stock WordPress vhost in [`wordpress.md`](wordpress.md) —
no Hummingbird-specific directive exists because there's nothing to key or
bypass beyond the baseline.

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
            cache_turbo               ct;
            cache_turbo_backend       wordpress;

            cache_turbo_valid         60s;
            cache_turbo_valid         404 410 1m;   # negative caching
            cache_turbo_preset        balanced;     # SWR: serve stale while one refresh runs

            # Belt and braces on top of the preset.
            cache_turbo_no_store      $cookie_wordpress_logged_in_;

            include                   fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_pass  unix:/run/php/php-fpm.sock;
        }

        location ~* \.(css|js|png|jpe?g|gif|webp|svg|woff2?)$ {
            cache_turbo off;
            expires 30d;
            access_log off;
            # Hummingbird's Browser Caching module sets its own long-lived
            # Cache-Control/Expires on these same responses — no conflict,
            # both point the same direction.
        }

        location = /_cache {
            cache_turbo_admin on;
            allow 127.0.0.1;
            deny  all;
        }
    }
}
```

## Multisite note

Hummingbird is a WPMU DEV product and commonly runs on WordPress
Multisite. Cache-turbo's default key already includes `$host`, so
subdomain-mapped multisite sites (`site2.example.com`) get naturally
separate cache entries with zero extra config. Subdirectory multisite
(`example.com/site2/`) is covered too, since `$uri` is also in the default
key — no special-casing needed either way.

## Purging on publish

Hummingbird fires `wphb_clear_page_cache` (and `wphb_clear_cache_url` for a
single URL) when it purges its *own* page cache on publish/update. With
Hummingbird's Page Caching module turned off per the short version above,
those hooks fire on an empty cache and are harmless no-ops — but they're
also the natural place to additionally purge cache-turbo, so the two systems
stay in lockstep if Page Caching is ever re-enabled by accident:

```php
add_action( 'wphb_clear_page_cache', function () {
    wp_remote_post( 'http://127.0.0.1/_cache?all=1' );
} );

add_action( 'wphb_clear_cache_url', function ( $url ) {
    wp_remote_post( 'http://127.0.0.1/_cache?key=' . rawurlencode( wp_make_link_relative( $url ) ) );
} );
```

Or hook the stock `save_post` / `transition_post_status` events directly, as
in [`wordpress.md`](wordpress.md#purging-on-publish) — either path reaches
the same admin endpoint. Remember a new post also changes the front page,
category archive, and feed; purge those keys too or accept the TTL.

## Gotchas

- **Double-cache if Page Caching is left on.** This is the one that matters:
  with both caches live, a purge in one system doesn't touch the other. A
  post edit that clears Hummingbird's disk cache still leaves a stale
  cache-turbo entry (or vice versa) until its TTL expires — readers can see
  either the old or the new version depending on which layer answered.
  Disable Hummingbird's Page Caching module; don't run two full-page caches
  stacked on the same site.
- **Asset Optimization/minify is safe to keep on.** It rewrites the HTML PHP
  emits (combining/minifying `<script>`/`<link>` tags) *before* cache-turbo
  ever sees the response — so a cache-turbo HIT serves the already-optimized
  markup. No conflict, no double work on the hit path.
- **Gzip/Browser Caching headers are safe to keep on** for the same reason —
  they're response-shaping, not request-routing; cache-turbo's cached copy
  already carries whatever headers PHP set on the MISS that stored it.
- **CDN module is safe to keep on** — it rewrites asset URLs in the HTML
  before cache-turbo stores it, same as Asset Optimization.
- **`is_user_logged_in()` gating:** Hummingbird's page cache gates logged-in
  users through WP core's `is_user_logged_in()`
  (`core/modules/class-page-cache.php:877-878`). If that check were ever the
  *only* thing standing between an authenticated page and a shared cache, it
  would be Hummingbird's job to get right, not cache-turbo's — but it doesn't
  matter here, because the stock `wordpress` preset's `wordpress_logged_in_*`
  bypass is the actual safety floor at the nginx layer regardless of what
  Hummingbird's PHP-side check does or doesn't catch.

## PHP settings / gotchas

Hummingbird-specific PHP/host behaviour worth knowing when cache-turbo fronts
the site:

- **The `advanced-cache.php` drop-in stays even with Page Caching "off" in
  the UI.** Activating the Page Caching module writes
  `wp-content/advanced-cache.php` and sets `define( 'WP_CACHE', true );` in
  `wp-config.php`. Toggling the module off in the dashboard removes the config,
  but a leftover drop-in or a `WP_CACHE` line that another plugin also wants can
  linger. If you want cache-turbo to own the front outright, confirm
  `wp-content/advanced-cache.php` is gone (or is not Hummingbird's) and that no
  stale `WP_CACHE` constant is loading a dead drop-in on every request — the
  drop-in runs in PHP before WordPress proper, so a stale one is pure overhead
  on a cache-turbo MISS. Hummingbird itself warns when it detects a foreign
  `advanced-cache.php` (`class-page-cache.php` around line 255).
- **`.htaccess`-based Gzip/Browser Caching are inert on nginx.** The Gzip and
  Browser Caching (Caching) modules auto-write only Apache rules —
  `mod_deflate` / `mod_expires` blocks into `.htaccess`
  (`class-gzip.php::get_apache_code()`, `class-caching.php::get_apache_code()`).
  On Angie/nginx nothing reads `.htaccess`, so those toggles do nothing on their
  own. The plugin *does* expose an nginx snippet (`get_nginx_code()`) for you to
  paste into the vhost by hand, but until you do, gzip and long-lived asset
  expiry come from the nginx config, not Hummingbird. This is why the static-asset
  `location` block above sets its own `expires 30d;` rather than relying on the
  plugin.
- **Asset Optimization runs PHP-FPM only on a cache MISS.** Minify/combine
  work (scanning, concatenating, minifying JS/CSS) happens while PHP renders the
  page — i.e. on the MISS that populates cache-turbo, never on a HIT. Budget
  PHP-FPM workers and `max_execution_time` for that heavier miss-path render; a
  cold cache after a purge storm briefly concentrates that cost. The output is
  baked into the HTML cache-turbo stores, so HITs pay nothing.
- **opcache matters on the miss path.** Because every Hummingbird MISS (and
  every request while its own drop-in lookup runs, if Page Caching is left on)
  executes PHP, keep opcache warm and sized so the Asset Optimization and
  drop-in code paths stay compiled. With cache-turbo absorbing the HITs, the PHP
  that does run is exactly the expensive render work opcache most helps.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [README — The cache key](../README.md#the-cache-key)
- [`wordpress.md`](wordpress.md) — the WordPress preset baseline this page builds on
- [`woocommerce.md`](woocommerce.md) — the WooCommerce add-on preset
- [`docs/README.md`](README.md) — all presets
</content>
