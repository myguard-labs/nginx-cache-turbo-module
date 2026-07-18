# Cache Enabler + cache-turbo

_Last researched: 2026-07-18_

Cache Enabler (KeyCDN, wordpress.org slug `cache-enabler`) is a deliberately
minimal page-cache plugin — no minify-the-kitchen-sink, no CDN bundling, just
static HTML on disk plus an optional WebP image-rewrite pass. That small
surface area makes the interop simple: turn its page cache off, keep
cache-turbo's `wordpress` preset, done.

- [The short version](#the-short-version)
- [How Cache Enabler caches](#how-cache-enabler-caches)
- [Cookies: nothing extra](#cookies-nothing-extra)
- [Vhost](#vhost)
- [WebP conversion — coupled to the page cache](#webp-conversion--coupled-to-the-page-cache)
- [Purging on publish](#purging-on-publish)
- [Gotchas](#gotchas)
- [See also](#see-also)

## The short version

Disable Cache Enabler's own page cache — cache-turbo does the same job a
layer closer to the client (nginx, not PHP). Settings → Cache Enabler →
untick **"Enable page caching for WordPress"**, or just deactivate the
plugin entirely; page caching is close to its whole feature set. Note that
CE's WebP conversion is **coupled to** the page cache — the URL rewrite runs
only inside CE's cache-store path (`Cache_Enabler_Disk::converter()`,
source-verified v1.8.16), so disabling CE's page cache disables its WebP
conversion too. There is no standalone-WebP mode (see
[WebP conversion](#webp-conversion--coupled-to-the-page-cache) below).

```nginx
cache_turbo         ct;
cache_turbo_backend wordpress;
```

No Cache-Enabler-specific preset — it needs none. It rides stock WordPress
identity checks with no cookie of its own, so the `wordpress` preset's
existing bypass rules already cover it exactly.

## How Cache Enabler caches

Confirmed from a direct source read of the current release (v1.8.16,
`inc/cache_enabler_disk.class.php` / `inc/cache_enabler_engine.class.php`):

- Writes static HTML to `wp-content/cache/cache-enabler/<host>/<path>/`,
  served through a `wp-content/advanced-cache.php` drop-in — **PHP-level**,
  evaluated on every request before WordPress fully boots. Unlike the
  Apache-only page-cache plugins, KeyCDN *also* publishes an official nginx
  `try_files` snippet that serves those files straight from nginx, skipping
  PHP entirely (see [PHP settings / gotchas](#php-settings--gotchas)) — but
  the plugin's own default path is the drop-in.
- Default cache-bypass cookie regex, straight from its settings:
  `/^(wp-postpass|wordpress_logged_in|comment_author)_/` — the exact same
  three WordPress-core cookie families the `wordpress` preset already
  bypasses on. **No plugin-specific cookie.**
- Purge functions live on the `Cache_Enabler` class: `clear_complete_cache()`,
  `clear_site_cache()`, `clear_page_cache_by_post()`, `clear_page_cache_by_url()`,
  `clear_expired_cache()`, `clear_page_cache_by_site()` (older
  `clear_page_cache_by_post_id` / `clear_site_cache_by_blog_id` are
  deprecated aliases). Wired to `save_post`, `pre_post_update`,
  `wp_trash_post`, comment/term/user-change hooks, `upgrader_process_complete`,
  plugin activate/deactivate, and WooCommerce stock-change hooks.

## Cookies: nothing extra

| Cookie | Treatment | Why |
|---|---|---|
| `wordpress_logged_in_*` | bypass (via `wordpress` preset) | same as stock WP |
| `wp-postpass_*` | bypass (via `wordpress` preset) | same as stock WP |
| `comment_author_*` | bypass (via `wordpress` preset) | same as stock WP |

Nothing to add. Cache Enabler doesn't mint an auth/session cookie of its
own, and its WooCommerce awareness (confirmed absent from the cache-decision
code path — it hooks stock-change events for *purging*, not cart-cookie
checks for *bypassing*) means a WooCommerce site still needs the
`woocommerce` preset add-on for cart/checkout bypass regardless of whether
Cache Enabler is installed:

```nginx
cache_turbo_backend wordpress woocommerce;
```

## Vhost

Same shape as [`wordpress.md`](wordpress.md) — Cache Enabler changes nothing
about the vhost once its own cache is switched off:

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

## WebP conversion — coupled to the page cache

Cache Enabler's WebP feature (`convert_image_urls_to_webp`) rewrites inline
`<img>` URLs to WebP copies **while it builds a cache file** — the rewrite
(`Cache_Enabler_Disk::converter()`) runs only inside the cache-store path and
only for the `-webp` cache variant. Two consequences, both source-verified
against v1.8.16 (correcting earlier notes in this doc):

- **It is `Accept`-header negotiated, not a static build-time pass.** The
  cache key carries a `-webp` component set from `Accept: image/webp`
  (`get_cache_keys()`), so CE stores and serves separate `https-index.html`
  and `https-index-webp.html` variants per request. There *is* Accept-header
  branching in the cache engine — the earlier "no Accept-header branching"
  claim was wrong.
- **It cannot run without CE's page cache.** WebP conversion happens as part
  of writing the cache file; there is no standalone image-rewrite path. Turn
  CE's page cache off and its WebP conversion goes with it.

So there is no "keep WebP, drop the cache" middle ground. Pick one:

- **cache-turbo as the single front cache (recommended):** disable CE
  entirely and accept that CE's WebP conversion goes too. cache-turbo caches
  whatever bytes/headers PHP returns; it does not itself rewrite images to
  WebP.
- **CE's WebP conversion:** keep CE's page cache **on** and do **not** put
  cache-turbo (or CE's nginx snippet) in front of it — let CE be the front
  cache. Running both is the double-front trap in [Gotchas](#gotchas).

## Purging on publish

The `wordpress.md` mu-plugin pattern applies unchanged — hook
`save_post` / `transition_post_status` and hit cache-turbo's own admin
endpoint:

```bash
curl -X POST 'http://127.0.0.1/_cache?key=example.com/blog/my-post/'
curl -X POST 'http://127.0.0.1/_cache?all=1'   # after a theme change
```

If you disable CE's page cache, its `Cache_Enabler::clear_*` hooks still fire
but no-op against an empty cache dir — harmless, nothing to unhook. (There is
no WebP-only mode to keep them busy: CE's WebP conversion is disabled along
with the cache — see [WebP conversion](#webp-conversion--coupled-to-the-page-cache).)

## Gotchas

- **Double-cache trap.** If Cache Enabler's own page cache is still on
  *and* cache-turbo is in front of it, a purge on one layer doesn't touch
  the other — a stale page can serve from whichever layer didn't get
  purged. Disable Cache Enabler's page cache; don't try to run both.
- **`advanced-cache.php` server-level bypass snippet.** If a previous setup
  used Cache Enabler's optional nginx "serve static file directly" snippet
  (skips PHP for the `wp-content/cache/cache-enabler/` files), remove it
  when adding cache-turbo — two competing HTML-serving layers in the same
  vhost is the same double-cache trap, just implemented in nginx instead of
  PHP.
- **No WebP-only mode.** You cannot keep Cache Enabler active "for WebP
  only" — its WebP conversion runs inside the page-cache store path and is
  disabled whenever page caching is off (source-verified v1.8.16). If you
  want cache-turbo as the front cache, disable CE fully and accept the loss
  of CE's WebP conversion; if you want CE's WebP, keep CE's page cache on and
  don't front it with cache-turbo.
- **On-disk cache layout (verified v1.8.16).** Files land at
  `wp-content/cache/cache-enabler/<host>/<path>/<scheme>-index[-mobile][-webp].html[.gz|.br]`
  — i.e. scheme-prefixed (`https-index.html`), with real `-mobile` (when the
  "mobile cache" setting is on) and `-webp` (Accept-negotiated) variant
  splits, plus optional precompressed `.gz`/`.br` twins. The earlier
  "`<host>/<uri>/index.html`" guess in this doc was incomplete — filenames
  are not a bare `index.html`. If auditing a specific install, list the
  actual `wp-content/cache/cache-enabler/` tree to confirm.

## PHP settings / gotchas

Cache-Enabler-specific notes on top of the [`wordpress.md`](wordpress.md) baseline.

- **CE's official nginx snippet double-fronts with cache-turbo — pick one
  (load-bearing).** Unlike the Apache-only page-cache plugins, KeyCDN
  publishes an *official nginx config* for Cache Enabler: a `try_files` block
  that serves the on-disk cache
  (`wp-content/cache/cache-enabler/$host/$uri/https-index….html`) straight
  from nginx, skipping PHP entirely. Deploy that snippet **and** cache-turbo
  in the same vhost and you have two independent front caches stacked — a
  purge on one layer never reaches the other, so a stale page can serve from
  whichever layer missed the purge. Do **not** install CE's nginx snippet
  when cache-turbo is the front cache. Run exactly one HTML-serving layer;
  this doc recommends cache-turbo (`cache_turbo_backend wordpress`) with CE's
  page cache disabled.
- **`advanced-cache.php` drop-in + `WP_CACHE` gating.** CE's PHP fast path is
  a `wp-content/advanced-cache.php` drop-in that WordPress loads *only* when
  `define( 'WP_CACHE', true )` is set. CE writes that constant into
  `wp-config.php` on activation and removes both the constant and the drop-in
  on deactivation (source-verified). If you disable CE's page cache but a
  stale drop-in or a lingering `WP_CACHE` remains (half-removed install), CE's
  engine still boots ahead of cache-turbo's origin and can re-serve its own
  stale HTML. When CE is the layer you turned off, confirm `WP_CACHE` is unset
  and `wp-content/advanced-cache.php` is gone.
- **WebP served by the snippet keys on `Accept`.** If instead you let CE be
  the front cache (snippet installed, cache-turbo not in front), its nginx
  snippet picks the `-webp` file by testing `Accept: image/webp`, and the
  `-mobile` / `.gz` / `.br` variants likewise — mirroring `get_cache_keys()`.
  cache-turbo is not in that path and needs no `Accept` handling of its own,
  because you are not running it there.
- **opcache.** CE's drop-in and engine classes are plain PHP evaluated on
  every origin request that misses cache-turbo; keep PHP opcache enabled so
  that fallback path stays cheap. Nothing CE-specific to tune beyond stock
  opcache.

## See also

- [`wordpress.md`](wordpress.md) — the baseline preset this doc builds on
- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [README — The cache key](../README.md#the-cache-key)
- [`woocommerce.md`](woocommerce.md) — needed alongside this if the site also runs WooCommerce
- [`docs/README.md`](README.md) — all presets
