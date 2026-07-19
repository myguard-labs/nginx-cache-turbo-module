# WP Super Cache + cache-turbo

_Last researched: 2026-07-18_

WP Super Cache is a PHP-level page-caching plugin for WordPress (~1M+ installs,
Automattic-maintained, one of the oldest WP caching plugins; verified here
against **v3.1.1**). It writes static
HTML to disk and serves it back through PHP (or, on Apache, via `mod_rewrite`).
This is an **interop** doc, not a backend preset — cache-turbo caches HTML pages
at the nginx layer, which is the same job WP Super Cache does at the PHP layer.
Running both is redundant at best and a stale-content trap at worst.

- [The short version](#the-short-version)
- [Its caching modes](#its-caching-modes)
- [Why not run both](#why-not-run-both)
- [Cookies: bypass vs key](#cookies-bypass-vs-key)
- [Vhost: page cache only](#vhost-page-cache-only)
- [Purging on publish](#purging-on-publish)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)
- [PHP settings / gotchas](#php-settings--gotchas)
- [See also](#see-also)

## The short version

**Disable WP Super Cache's caching entirely** — Settings → WP Super Cache →
uncheck "Caching On" (or delete/deactivate the plugin) — and let cache-turbo own
the HTML page cache at the nginx layer. Use the plain `wordpress` preset:

```nginx
cache_turbo         ct;
cache_turbo_backend wordpress;
```

WP Super Cache is essentially *only* a page cache — it has no meaningful CDN,
image-optimization, or minification features of its own to keep around, so
disabling its caching function is close to disabling the whole plugin. There is
no supported "coexist" mode: it is not designed to sit downstream of another
full-page cache, and nothing in the plugin detects or defers to one.

If you can't remove it immediately (rollout constraints, staged migration),
see [Why not run both](#why-not-run-both) for the narrowest-blast-radius
fallback — but treat that as temporary, not a target state.

## Its caching modes

WP Super Cache ships three delivery modes:

| Mode | Mechanism | Works on nginx? |
|---|---|---|
| **Expert** | Apache `mod_rewrite` rules in `.htaccess`/vhost serve a pre-generated static HTML file, bypassing PHP entirely | **No** — `mod_rewrite` is an Apache module. On nginx the rewrite rules are simply never evaluated. The plugin explicitly detects nginx (`$is_nginx`): it does **not** write the `.htaccess` rules there, and its settings page swaps in a note that "Nginx rules can be found here but are not officially supported," linking to WordPress's manual-nginx-config doc instead of generating any config itself (confirmed in `partials/advanced.php`, v3.1.1). |
| **Simple** | PHP-level: WordPress boots, the plugin intercepts early and serves a cached HTML file from PHP, no `.htaccess` changes | Yes — the only mode that functions correctly on an nginx/PHP-FPM stack |
| **WP-Cache (legacy)** | Same PHP-level mechanism as Simple, but also caches variant pages for logged-in users / query strings / feeds; always on underneath the other two modes | Yes, same as Simple |

The plugin does **not** ship an nginx-native equivalent of Expert mode. Various
third-party guides show a hand-built `fastcgi_cache`/`try_files` nginx config as
a substitute for Expert mode's speed — that is effectively reinventing what
cache-turbo already does, better (SWR, Redis L2, per-CMS bypass rules, atomic
purge). If you found one of those guides, **use cache-turbo instead**; don't
also run WP Super Cache in Simple mode underneath it.

## Why not run both

If WP Super Cache's PHP-level cache is left on behind cache-turbo, you get a
double cache with independent TTLs and no shared invalidation:

1. A page changes. You purge cache-turbo's key (or wait out its TTL).
2. The next request that reaches PHP — during the purge window, or because
   cache-turbo's SWR background-refresh hit the origin — can be served **WP
   Super Cache's own stale static file** instead of a fresh render, since WP
   Super Cache intercepts before WordPress finishes booting.
3. cache-turbo then caches *that* stale response. Net effect: the page can be
   stale for the sum of both TTLs, not just cache-turbo's, and purging
   cache-turbo alone no longer guarantees a fresh page.

There's no compensating upside — WP Super Cache's PHP cache is not meaningfully
faster than a PHP-FPM origin for the rare requests that actually reach it once
cache-turbo is in front (anonymous-guest misses, background SWR refreshes), and
it adds a second cache layer to keep in sync on every purge.

## Cookies: bypass vs key

WP Super Cache adds no cookie of its own beyond stock WordPress. It detects
"known users" (logged-in, commented, password-protected-post viewers) using the
**same** cookies WordPress core sets, and its `wpsc_add_cookie`/
`wpsc_delete_cookie` hooks only let a site owner extend that list, not replace
it (both confirmed as `add_action` hooks in `wp-cache.php`, v3.1.1; the
underlying reliance on core cookies is the load-bearing fact). The
`wordpress` preset in [`wordpress.md`](wordpress.md) already covers this —
nothing extra to add for WP Super Cache specifically:

| Cookie | Treatment | Why |
|---|---|---|
| `wordpress_logged_in_*` | **bypass** | authenticated user — same signal WP Super Cache itself checks |
| `wp-postpass_*` | **bypass** | password-protected post viewer |
| `comment_author_*` | **bypass** | WP Super Cache serves these visitors a personalized (non-static) variant too |

## Vhost: page cache only

Same syntax as [`wordpress.md`](wordpress.md) — WP Super Cache's caching is
switched off in its own settings screen, so there's nothing plugin-specific in
the vhost. Point cache-turbo straight at the WordPress preset:

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

## Purging on publish

WP Super Cache clears its own static files on publish via `wpsc_post_transition`
(hooked on `transition_post_status`), plus `wp_cache_clear_cache_on_menu` on
`wp_update_nav_menu`; both call the plugin's `wp_cache_clear_cache()` (confirmed
in `wp-cache-phase2.php`, v3.1.1). With WP Super Cache's caching
disabled, that hook has nothing to clear — wire the same trigger point to
cache-turbo's admin endpoint instead:

```bash
curl -X POST 'http://127.0.0.1/_cache?key=example.com/blog/my-post/'
curl -X POST 'http://127.0.0.1/_cache?all=1'          # after a theme/plugin change
```

Add this from a `save_post` mu-plugin, same as the stock WordPress recipe in
[`wordpress.md`](wordpress.md#purging-on-publish) — purge the post URL, the
front page, and the relevant category archive/feed keys.

## Checking it works

```nginx
add_header X-Cache-Turbo $cache_turbo_status always;
```

```bash
# anonymous post: MISS then HIT
curl -sI https://example.com/blog/hello/ | grep -i x-cache-turbo
curl -sI https://example.com/blog/hello/ | grep -i x-cache-turbo   # HIT

# logged-in: must always be BYPASS
curl -sI -H 'Cookie: wordpress_logged_in_abc=user|123|hash' \
     https://example.com/blog/hello/ | grep -i x-cache-turbo       # BYPASS
```

Also confirm WP Super Cache is actually off: its admin bar / settings screen
should show "Caching Off", and `wp-content/cache/supercache/` should stop
growing new files after you disable it (existing stale files there are inert
once the plugin stops serving them — safe to leave or clear at your convenience).

## Gotchas

> **Subdirectory installs.** This preset's URI rules are root-relative literals
> matched from byte 0 of `r->uri`, so an install mounted under a subdirectory
> (`/shop/`, `/forum/`, …) matches **none** of them — the admin surface
> included. Declare the mount with `cache_turbo_backend_prefix /forum/;` and the
> preset URI tier is compared against the rebased path. Scoping the nginx
> `location` does **not** substitute: it routes requests, it does not rewrite
> `r->uri`. See [frameworks.md](frameworks.md).

- **Expert/mod_rewrite mode is inert on nginx today — but don't ever turn it
  on.** Its `.htaccess` rewrite rules are Apache-only directive syntax; nginx
  never reads `.htaccess` and never evaluates them, so enabling Expert mode on
  a pure-nginx box does nothing (not even a wasted no-op — it's just dead
  config). The real risk is a **future hybrid deployment** (an Apache tier
  added in front of or behind nginx, or a migration path through Apache): if
  Expert mode's static-file rewrite rules become live in that setup while
  cache-turbo also runs, you get two independent full-page caches with
  separate write paths and no shared purge — the exact double-cache problem in
  [Why not run both](#why-not-run-both), except now via URL rewriting instead
  of PHP interception, and much harder to spot because the Apache layer serves
  files straight off disk without going near WordPress or cache-turbo's purge
  hook at all. Leave Expert mode off; don't let a future infra change flip it
  on silently.
- **Don't chase the plugin's own "nginx caching" guides.** Various blog posts
  and even old plugin-adjacent docs show a hand-rolled `fastcgi_cache`
  `try_files` config as an nginx substitute for Expert mode
  (unverified/community-reported — not an official WP Super Cache deliverable,
  but widely circulated). It's the same job cache-turbo does with SWR, Redis
  L2, and CMS-aware bypass rules built in — use cache-turbo, not a bespoke
  `fastcgi_cache` block, and don't run both.
- **Stale `wp-content/cache/supercache/` files after disabling.** Turning off
  "Caching On" stops new writes but doesn't delete existing static files. They
  won't be served (the plugin's PHP-level intercept is what serves them, and
  it's now disabled) but clear the directory if you want the disk space back.
- **WooCommerce or other add-on presets stack independently.** If the site also
  needs WooCommerce's dynamic-cart bypass rules, compose as in
  [`wordpress.md`](wordpress.md): `cache_turbo_backend wordpress woocommerce;`
  — nothing here changes that.

## PHP settings / gotchas

WP-Super-Cache-specific PHP behaviours to be aware of once cache-turbo owns the
nginx front. They matter mostly if the plugin is kept installed (staged
migration) rather than removed outright.

- **Expert/`mod_rewrite` mode is Apache-only and inert on nginx.** Setting
  `wp_cache_mod_rewrite = 1` (the "Expert" radio) only ever emits `.htaccess`
  rewrite rules, and the plugin guards that write behind `! $is_nginx` — on nginx
  it writes nothing and every request falls through to the PHP serving path in
  `advanced-cache.php`. Net effect: on nginx, Expert mode silently degrades to the
  same PHP-level serve as Simple mode. Leave it on **Simple**
  (`wp_cache_mod_rewrite = 0`) so the configured mode matches what actually runs.
- **Two PHP drop-ins.** The plugin installs `wp-content/advanced-cache.php`
  (pulled in on every request via the `WP_CACHE` constant in `wp-config.php`,
  before WordPress finishes booting) and reads its settings from
  `wp-content/wp-cache-config.php`. Both keep executing even behind cache-turbo —
  for the anonymous requests cache-turbo already absorbs, `advanced-cache.php` is
  pure PHP overhead. Deactivating the plugin removes the `WP_CACHE` define and the
  drop-in; disabling only "Caching On" leaves the drop-in in place.
- **Garbage-collection cron is PHP load.** The `wp_cache_gc` scheduled event
  (Timer/Clock schedulers under Advanced) walks and prunes `wp-content/cache/` on
  a PHP worker. With the plugin's cache disabled there is nothing to collect, but
  the cron may still be scheduled — clear it
  (`wp_clear_scheduled_hook( 'wp_cache_gc' )`) or just deactivate the plugin so it
  is not burning a PHP-FPM slot on an empty directory.
- **Preload mode hammers PHP-FPM.** The preloader (`wp_cache_preload_hook` /
  `wp_cache_full_preload_hook`) crawls the whole site to warm its own static
  files, driving a burst of full PHP renders. Behind cache-turbo this warms the
  *wrong* cache (the PHP one, not the nginx front) while competing with real
  traffic for FPM workers — leave preload **off**. cache-turbo fills on first
  anonymous hit and via its own SWR refresh; it needs no plugin preloader.
- **opcache.** `advanced-cache.php` and the config drop-in benefit from opcache
  like any PHP file, but nothing in WP Super Cache needs special opcache tuning —
  the general PHP-FPM/opcache guidance in [`wordpress.md`](wordpress.md) applies
  unchanged.
- **`wp_cache_no_cache_for_get`.** The plugin's "Don't cache pages with GET
  parameters" setting only governs *its own* PHP cache; it has no effect on
  cache-turbo's key. Query-string handling for the nginx front is set by the
  `wordpress` preset and your `cache_turbo` config, not by this checkbox.

## See also

- [`../README.md`](../README.md) — CMS backends and the cache key
- [`wordpress.md`](wordpress.md) — the WordPress preset baseline this doc builds on
