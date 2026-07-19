# Breeze + cache-turbo

_Last researched: 2026-07-18_

Interop notes for **Breeze**, Cloudways' free WordPress caching plugin
(`wordpress.org/plugins/breeze`, ~70k+ installs). This is **not** a new
`cache_turbo_backend` preset — Breeze is a WordPress plugin, so the stock
`wordpress` preset already covers it. This doc exists because Breeze has one
platform-specific wrinkle (its Cloudways Varnish toggle) worth calling out
explicitly.

- [The short version](#the-short-version)
- [What Breeze actually is](#what-breeze-actually-is)
- [Cookies: one, and it is not an identity](#cookies-one-and-it-is-not-an-identity)
- [Scenario 1: self-hosted / non-Cloudways nginx](#scenario-1-self-hosted--non-cloudways-nginx)
- [Scenario 2: on Cloudways-managed infra](#scenario-2-on-cloudways-managed-infra)
- [Vhost: page cache only](#vhost-page-cache-only)
- [Purging on publish](#purging-on-publish)
- [Gotchas](#gotchas)
- [PHP settings / gotchas](#php-settings--gotchas)
- [See also](#see-also)

## The short version

Two scenarios, decided entirely by *where the site is hosted*, not by
anything cache-turbo can detect automatically:

1. **Self-hosted / any non-Cloudways nginx (the case this module targets):**
   disable Breeze's own page cache, keep its minify/gzip/CDN features, and let
   cache-turbo own the page cache with the stock `wordpress` preset:

   ```nginx
   cache_turbo         ct;
   cache_turbo_backend wordpress;
   ```

2. **On Cloudways-managed infrastructure** (their own Varnish + a
   platform-managed nginx/Apache layer you don't configure yourself): this
   module's normal self-managed-vhost deployment model likely doesn't apply —
   see the brief note below, not overbuilt further.

## What Breeze actually is

Confirmed via the plugin's own listing and Cloudways' support docs: Breeze is
a disk-based static-HTML page cache, same family as WP Fastest Cache / Cache
Enabler — it writes cached HTML to disk and serves it through WordPress's
advanced cache mechanism (an `advanced-cache.php` drop-in), a PHP-level cache
that still runs inside the WordPress request lifecycle rather than in front
of it. On top it bundles CSS/JS minification, gzip, and CDN URL rewriting —
those parts are host-agnostic and worth keeping regardless of which layer
owns the page cache.

Separately, Breeze ships a "Varnish" toggle. On Cloudways it flushes their
platform-managed Varnish, but — confirmed against plugin source (v2.5.9) — the
integration is **not** Cloudways-locked: the Varnish tab exposes a "Varnish
Server IP" field (`breeze-varnish-server-ip`, default `127.0.0.1`), and "Auto
Purge Varnish" sends `PURGE`/`URLPURGE` requests at whatever host you point it
at on save/edit/delete/comment. The catch is a runtime gate —
`is_varnish_cache_started()` only lets the purge fire when Varnish is actually
detected (an `X-Varnish` response header, or an `X-Cache` header on a probe
request, result cached 24h). So with no Varnish in front at all, detection
fails and the toggle is effectively inert; put your own Varnish ahead of nginx
and set the IP, and it becomes a live self-hosted purge integration. Either
way it never touches cache-turbo's zone — Varnish would sit in front of nginx,
cache-turbo lives inside it.

## Cookies: one, and it is not an identity

Checked Breeze's settings surface and support docs for a plugin-specific
identity cookie (the pattern XenForo's `xf_session` or a bespoke "logged in"
cookie would represent). **Confirmed: no identity cookie.** Breeze's "cache
logged-in users" option is a coarse per-role toggle (Administrator/Editor/
Author/Contributor) evaluated server-side against WordPress's own
`wordpress_logged_in_*` cookie at cache-write time — it does not mint a
login cookie of its own for the browser to carry.

**It does mint one non-identity cookie, and it has a real edge case.** Breeze
sets `breeze_commented_posts[<post-id>]` from its `set_comment_cookies` hook
(`purge-cache.php`), **without the consent check WordPress core applies to its
own `comment_author_*` cookies**. So a commenter who *declines* the cookie
consent box carries the Breeze cookie **alone**: core skips `comment_author_*`,
the `wordpress` preset has nothing to match on, and that commenter is served a
cached page on which their own pending comment is missing. It is a confusing-UX
bug, not a leak — the cookie carries no identity — but if your site takes
comments, add it:

```nginx
map $http_cookie $breeze_commenter {
    default                                  0;
    "~*(^|;\s*)breeze_commented_posts%5B"    1;
}

cache_turbo_bypass   $breeze_commenter;
cache_turbo_no_store $breeze_commenter;
```

Otherwise the stock `wordpress` preset's bypass list is complete for Breeze:

| Check | Values |
|---|---|
| URI prefixes | `/wp-admin/`, `/wp-login.php`, `/wp-cron.php`, `/xmlrpc.php`, `/wp-json/` |
| Cookie header substrings | `wordpress_logged_in_`, `wp-postpass_`, `comment_author_` |

> **Subdirectory installs.** The URI prefixes above are root-relative literals
> matched from byte 0 of `r->uri`, so an install mounted under a subdirectory
> (`/shop/`, `/forum/`, …) matches **none** of them — the admin surface
> included. Declare the mount with `cache_turbo_backend_prefix /shop/;` and the
> preset URI tier is compared against the rebased path. Scoping the nginx
> `location` does **not** substitute: it routes requests, it does not rewrite
> `r->uri`. See [frameworks.md](frameworks.md).

No Breeze-specific row to add. See [`wordpress.md`](wordpress.md) for the
full table and the reasoning behind each entry.

## Scenario 1: self-hosted / non-Cloudways nginx

This is the deployment cache-turbo is built for: you own the nginx vhost.
Disable Breeze's own disk page cache (Breeze settings → Basic Settings →
turn off "Enable Caching" for the page-cache section specifically — leave
minification, gzip and CDN settings alone, those aren't page-cache overlap).
Point `cache_turbo_backend wordpress;` at the vhost exactly as in
[`wordpress.md`](wordpress.md) — no Breeze-specific directive is needed
because there is no Breeze-specific cookie or URI surface to bypass beyond
stock WordPress.

## Scenario 2: on Cloudways-managed infra

Kept brief on purpose — this is out of scope for a self-managed nginx module.
Cloudways runs their own Varnish + platform-managed web server layer; you
typically don't hand-edit an nginx vhost the way this module's docs assume.
If you're running cache-turbo as a dynamic module inside a **self-managed**
nginx on a Cloudways VM (bypassing their managed stack entirely — an
unusual but possible setup), the same Scenario 1 guidance applies: disable
Breeze's local disk cache, let cache-turbo own the page cache, and treat
Breeze's Varnish toggle as somebody else's cache to leave alone or turn off
per their own docs. Otherwise, this module isn't the tool for the managed
Cloudways stack — use Breeze's native Varnish integration as intended.

## Vhost: page cache only

Identical to the WordPress baseline — reuse it verbatim, no Breeze-specific
directives:

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

For the self-hosted scenario, wire cache-turbo's own admin endpoint from the
same `save_post` / `transition_post_status` hook the WordPress doc describes:

```bash
curl -X POST 'http://127.0.0.1/_cache?key=example.com/blog/my-post/'
curl -X POST 'http://127.0.0.1/_cache?all=1'          # after a theme change
```

If Breeze's own disk cache is disabled per Scenario 1, its purge-on-publish
hook has nothing left to clear on the disk-cache side — safe to leave
enabled (it becomes a no-op against an empty cache dir) or disable it
alongside the page-cache toggle. The Varnish purge action, if Breeze's Varnish
toggle is on, is a **separate concern**: it fires at whatever host
`breeze-varnish-server-ip` points to (Cloudways' managed layer by default, or
your own Varnish if you set the IP), and only once Varnish is detected — it has
no interaction with cache-turbo's zone either way, since Varnish sits in front
of nginx rather than inside it.

## Gotchas

- **Double-cache warning.** Leaving Breeze's disk page cache enabled
  alongside cache-turbo means two page-cache layers stacked on the same
  requests — stale content can get served from whichever layer's TTL hasn't
  expired yet, and purge-on-publish has to fire on both to actually clear a
  page. Disable one. This module's docs consistently recommend disabling the
  plugin-level cache and letting cache-turbo own the page cache — it sits in
  front of PHP entirely rather than inside it.
- **Varnish toggle is a configurable host, not Cloudways-only.** The Varnish
  tab takes a server IP (`breeze-varnish-server-ip`, default `127.0.0.1`) and
  only purges once Varnish is detected. With no Varnish present it's inert
  (detection fails, nothing fires); if you run your own Varnish in front of
  nginx and set the IP, Breeze purges it on publish. That never overlaps
  cache-turbo's zone (Varnish in front of nginx, cache-turbo inside), but it's
  a second purge path to keep in mind.
- **Minify/gzip/CDN features are unaffected either way** — they operate on
  the HTML/asset output regardless of which layer owns the page cache, so
  there's no need to disable them when disabling Breeze's page cache.
- **No Breeze-specific *identity* cookie exists** (confirmed against plugin
  source v2.5.9 — its page cache keys off WordPress's own
  `wordpress_logged_in_` cookie and mints no login cookie of its own). It does
  mint `breeze_commented_posts[<id>]` with no consent gate, which is the one
  real gap — see [Cookies](#cookies-one-and-it-is-not-an-identity) above. If a future release
  adds a dedicated logged-in marker, it would need a `cache_turbo_bypass` +
  `cache_turbo_no_store` addition (the bypass alone still stores) the way
  XenForo's `xf_lscxf_logged_in` needed one.

## PHP settings / gotchas

Breeze-specific runtime notes, on top of the cache-layer gotchas above:

- **`advanced-cache.php` drop-in + `WP_CACHE`.** Breeze's page cache runs as a
  drop-in loaded before WordPress boots: enabling it writes
  `wp-content/advanced-cache.php` and sets `define('WP_CACHE', true)` in
  `wp-config.php`. In Scenario 1 keep the page cache **off** so this drop-in
  isn't serving stale HTML from inside PHP while cache-turbo caches in front of
  it. If a stale drop-in lingers after deactivation, delete
  `wp-content/advanced-cache.php` and unset `WP_CACHE`.
- **opcache.** The drop-in and minify maps are plain PHP under
  `wp-content/cache/`; with `opcache.validate_timestamps=0` a purge that
  rewrites them won't take effect until opcache is reset — flush opcache (or
  the PHP-FPM pool) alongside a Breeze purge.
- **No object-cache backend of its own.** Breeze ships no Redis/Memcached
  drop-in — its "Purge Object Cache" just calls `wp_cache_flush()` and steps
  aside for Redis Object Cache Pro (`WP_REDIS_VERSION`) when present. Add a real
  `object-cache.php` drop-in yourself if you want persistent object caching;
  cache-turbo's page cache is unaffected either way.
- **Varnish detection probe.** With "Auto Purge Varnish" on, Breeze issues a
  self-request (`?breeze_check_cache_available=`) to sniff for a Varnish
  `X-Cache`/`X-Varnish` header, result cached 24h. Harmless, but it's why the
  toggle can look "dead" for up to a day after you stand up a Varnish layer.

## See also

- [`wordpress.md`](wordpress.md) — the baseline WordPress preset this doc
  builds on; full cookie table and vhost reasoning.
- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [README — The cache key](../README.md#the-cache-key)
- [`docs/README.md`](README.md) — all presets
