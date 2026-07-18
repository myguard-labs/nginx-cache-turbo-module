# WP Fastest Cache + cache-turbo

_Last researched: 2026-07-18_

WP Fastest Cache (wordpress.org slug `wp-fastest-cache`, ~1M+ installs) is a
WordPress plugin that both writes its own static-HTML page cache **and** offers
minify/combine/CDN/browser-cache-header tooling. This doc is **not** a new
`cache_turbo_backend` preset — it's an interop guide for running cache-turbo
alongside it without the two page caches fighting.

- [The short version](#the-short-version)
- [Why not run both HTML caches](#why-not-run-both-html-caches)
- [Cookies: bypass vs key](#cookies-bypass-vs-key)
- [Vhost: page cache only](#vhost-page-cache-only)
- [Purging on publish](#purging-on-publish)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)
- [PHP settings / gotchas](#php-settings--gotchas)
- [See also](#see-also)

## The short version

Run the stock `wordpress` preset (see [`wordpress.md`](wordpress.md)) and let
cache-turbo own the page cache. In WP Fastest Cache's settings:

- **Disable "Cache System"** (its HTML page-cache engine) — this is the one
  overlapping feature.
- **Keep** Minify HTML, Minify CSS, Combine CSS, Minify JS, Combine JS, CDN
  integration, and the browser-cache (`Cache-Control`/`expires`) header
  options if you find them useful — none of these duplicate what cache-turbo
  does, they change what the *origin* emits, which cache-turbo then caches
  once and serves many times.

```nginx
cache_turbo         ct;
cache_turbo_backend wordpress;
```

No WP-Fastest-Cache-specific bypass rules are needed — see cookies below.

## Why not run both HTML caches

WP Fastest Cache's page-cache mechanism writes static files to
`wp-content/cache/all/<uri>/index.html` (confirmed: plugin docs and its own
published nginx sample both reference this path). On Apache it serves them via
`.htaccess` `mod_rewrite`, checking the filesystem before PHP ever loads. On
**nginx there is no `.htaccess`/`mod_rewrite`**, so the plugin needs an
explicit nginx config to reproduce that filesystem short-circuit — its
published sample (see below) uses `try_files` against the same
`wp-content/cache/all/` paths, still bypassing PHP for a hit. If that nginx
snippet is **not** installed, there is **no PHP-level short-circuit at all**:
unlike some cache plugins, the free WP Fastest Cache ships **no**
`advanced-cache.php` drop-in (verified in the 1.4.9 source — it sets `WP_CACHE`
only as a narrow compatibility shim when the wp-postviews plugin is active, never
as a serving path). WordPress boots fully on every request, the plugin's
output-buffer hook re-renders the page and merely repopulates its own disk cache
— a full PHP render, far slower than either the plugin's own `try_files`
short-circuit or a pure cache-turbo nginx-layer HIT that never touches PHP-FPM at
all.

Either way — `try_files`-served or PHP-served — running WP Fastest Cache's page
cache **underneath** cache-turbo buys nothing: a cache-turbo HIT never reaches
nginx's `location ~ \.php$` block at all, so WP Fastest Cache's disk cache is
dead weight for every request that matters. It only fires on a cache-turbo
MISS/bypass, at which point you've paid for two page caches to store
functionally the same HTML. Turn its HTML caching off; let cache-turbo be the
only page cache in the stack.

## Cookies: bypass vs key

WP Fastest Cache does **not** define its own session/login cookie for cache
exclusion. Its "Exclude logged in users" setting checks WordPress core's
standard `wordpress_logged_in_*` auth cookie — the same cookie the
`wordpress` preset already bypasses on. No additional cookie name is needed.

| Cookie | Treatment | Why |
|---|---|---|
| `wordpress_logged_in_*` | **bypass** (preset default) | WP Fastest Cache's own "exclude logged-in users" relies on this same cookie — nothing extra to add |
| `wp-postpass_*` | **bypass** (preset default) | password-protected post reader |
| `comment_author_*` | **bypass** (preset default) | WP core personalizes the comment form for them |

Per-page/per-cookie exclusion (the plugin's own "Exclude" rules UI, e.g.
excluding `woocommerce_items_in_cart`) is a **WP-Fastest-Cache-internal**
setting that only matters if you leave its own HTML caching on. With its
HTML caching disabled per this doc, those rules are moot — cache-turbo's own
bypass/key rules (stock `wordpress` preset, plus `woocommerce` if relevant —
see [`woocommerce.md`](woocommerce.md)) are what actually govern the shared
edge cache.

*Unverified/community-reported:* some users report new cache files aren't
regenerated when "Cache logged-in Users"-style options are combined with
certain other settings — a plugin-internal quirk, irrelevant once its HTML
caching is turned off.

## Vhost: page cache only

Identical to the stock WordPress vhost in [`wordpress.md`](wordpress.md) — WP
Fastest Cache needs no special nginx handling once its own HTML cache is
disabled, because there's no `wp-content/cache/all/` `try_files` short-circuit
to wire in.

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
        }

        location = /_cache {
            cache_turbo_admin on;
            allow 127.0.0.1;
            deny  all;
        }
    }
}
```

> **Official plugin nginx sample supersedes.** WP Fastest Cache publishes its
> own nginx snippet (`try_files` against `wp-content/cache/${host}/all${uri}`
> and `wp-content/cache/all${uri}`, with `error_page 418 = @cachemiss` /
> `419 = @mobileaccess` routing — the host-prefixed and `wpfc-mobile-cache`
> paths are confirmed in the 1.4.9 source; the exact `error_page` snippet is
> from the plugin's published nginx guide, unverified against the source tree)
> for sites running its HTML cache directly on nginx. **Do not use that snippet
> here** — it exists to serve *its own* disk cache, which this doc recommends
> disabling. The vhost above (cache-turbo only) replaces it.

## Purging on publish

Same shape as the stock WordPress flow in [`wordpress.md`](wordpress.md) — wire
cache-turbo's admin/purge endpoint from WordPress's publish hook. WP Fastest
Cache's own `WpFastestCache::deleteCache()` runs on its `on_all_status_transitions`
hook (confirmed in the plugin source: publish-status transitions trigger its
internal cache clear) — that call is harmless to leave in place even with its
HTML caching disabled, but it purges *its own* (now-empty) disk cache, not
cache-turbo's. Add cache-turbo's own purge alongside it in a mu-plugin:

```php
add_action( 'transition_post_status', function ( $new_status, $old_status, $post ) {
    if ( $new_status !== 'publish' ) {
        return;
    }
    // The admin endpoint hashes ?key= verbatim -- it must equal the full
    // cache key (host + uri + normalized args), not the scheme+host+path
    // that get_permalink() returns.
    $key = preg_replace( '#^https?://#', '', get_permalink( $post ) );
    wp_remote_post( 'http://127.0.0.1/_cache?key=' . rawurlencode( $key ) );
}, 10, 3 );
```

```bash
curl -X POST 'http://127.0.0.1/_cache?key=/blog/my-post/'
curl -X POST 'http://127.0.0.1/_cache?all=1'          # after a theme/minify-settings change
```

As with stock WordPress, also purge the front page, relevant category
archives, and the feed — or accept the TTL on them. A change to WP Fastest
Cache's own minify/combine settings changes the HTML/CSS/JS every cached page
serves, so treat a settings save there the same as a theme change: `?all=1`.

## Checking it works

```nginx
add_header X-Cache-Turbo $cache_turbo_status always;
```

```bash
curl -sI https://example.com/blog/hello/ | grep -i x-cache-turbo   # MISS
curl -sI https://example.com/blog/hello/ | grep -i x-cache-turbo   # HIT

curl -sI -H 'Cookie: wordpress_logged_in_abc=user|123|hash' \
     https://example.com/blog/hello/ | grep -i x-cache-turbo       # BYPASS
```

Also confirm WP Fastest Cache's own cache is actually off:
`wp-content/cache/all/` should not be growing new `index.html` files after a
purge-and-revisit cycle. If it is, its "Cache System" toggle is still on.

## Gotchas

- **Leaving "Cache System" on stacks both caches for no benefit.** WP Fastest
  Cache's output-buffer cache hook runs *inside* the PHP request path (there is
  no `advanced-cache.php` drop-in in the free plugin) — a cache-turbo HIT never
  reaches PHP at all, so the plugin's cache is never consulted on a hit. A
  cache-turbo MISS or bypass, though, hits
  **both**: PHP renders, WP Fastest Cache writes its own disk-cache copy of
  the exact same response cache-turbo is about to store at the edge anyway.
  Pure wasted disk I/O with zero improvement to what the visitor experiences —
  turn "Cache System" off.
- **The plugin's minify/combine output still needs a cache-turbo purge.**
  Changing minify/combine/CDN settings regenerates the CSS/JS the *next*
  origin render will emit, but any already-cached HTML in cache-turbo still
  points at the old asset URLs/hashes until you purge (`?all=1`).
- **Don't install the plugin's own nginx `try_files` snippet.** It exists to
  serve `wp-content/cache/all/` directly — with HTML caching disabled that
  directory stays empty and the snippet is dead weight (and if it somehow
  DOES ever find files there, it's serving stale content cache-turbo doesn't
  know about).
- **Premium version.** WP Fastest Cache Premium adds features (image
  optimization, additional CDN options) that don't change any of the above —
  the free version's "Cache System" toggle is the one that matters here, and
  it's present in both tiers.

## PHP settings / gotchas

WP-Fastest-Cache-specific PHP-side behaviour worth knowing when it runs behind
cache-turbo on nginx/Angie. None of this changes the cache-turbo config above —
it's about what the plugin does inside PHP-FPM.

- **`.htaccess`/`mod_rewrite` delivery is inert on nginx.** WP Fastest Cache's
  page cache *and* its WebP delivery are driven by rules it writes into
  `.htaccess` (`# BEGIN WpFastestCache … RewriteRule` for the HTML cache,
  `# BEGIN WEBPWpFastestCache …` for WebP). Angie/nginx never reads `.htaccess`,
  so every one of those rules is dead — the plugin's admin panel can still report
  the cache as "active" while, on the wire, delivery falls through to a full
  PHP-FPM render (WordPress boots, the plugin's output-buffer hook re-renders and
  repopulates its disk cache). This is the mechanism behind disabling its page
  cache entirely: on nginx it was never short-circuiting anything cache-turbo
  doesn't already do at the edge.
- **Preload hammers PHP-FPM.** The preload feature (and its sitemap-preload
  variant) walks your URL list and fetches each one with `wp_remote_get()`
  (verified in the 1.4.9 source) — a real HTTP request back into the site,
  `wpFastestCachePreload_number` at a time (default 4). Every fetch is a full
  origin render through PHP-FPM. With cache-turbo owning the front, warming the
  plugin's now-disabled disk cache buys nothing but load — leave preload **off**
  and let cache-turbo warm naturally (or via its own admin/purge tooling). If you
  do run it for some other reason, keep `wpFastestCachePreload_number` low so it
  doesn't saturate the FPM pool.
- **Image optimization / WebP is a premium, origin-side concern.** Image
  optimization lives in WP Fastest Cache **Premium**
  (`WpFastestCacheImageOptimisation`), and its WebP *delivery* is the `.htaccess`
  rule block above — inert on nginx. If you want WebP served, do it at the origin
  (the premium optimizer rewrites `<img>`/`<picture>` markup in the buffered HTML,
  which cache-turbo then caches as-is) or at the nginx layer; don't rely on the
  plugin's `mod_rewrite` WebP switch. Either way it only changes what the origin
  emits on a MISS — treat a WebP/optimization settings change like a minify change
  and purge cache-turbo (`?all=1`).
- **opcache.** The plugin is ordinary PHP; keep PHP-FPM opcache on as usual. Its
  minify/combine writes new asset files under `wp-content/cache/wpfc-minified/`,
  but those are static `.css`/`.js` served straight off disk — not PHP — so
  opcache never touches them, and no opcache reload is needed after a
  minify-settings change (a cache-turbo `?all=1` purge is — see above). Only a
  plugin *update* changes the `.php` files opcache holds.
- **`wpfc-*` cache directories.** With its page cache off you'll still see the
  plugin create sibling dirs under `wp-content/cache/`: `wpfc-minified/`
  (minified CSS/JS — keep it, that's the origin-speedup half) and, if mobile or
  widget caching ever ran, `wpfc-mobile-cache/` and `wpfc-widget-cache/`. Only
  `all/` is the HTML page cache this doc tells you to disable; the `wpfc-*`
  siblings are asset/fragment caches and are safe (and useful) to leave. Don't
  point any nginx `try_files` at `all/` — see the vhost note above.

## See also

- [`wordpress.md`](wordpress.md) — the baseline WordPress preset this doc
  builds on (cookie table, vhost, purge-on-publish pattern)
- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [README — The cache key](../README.md#the-cache-key)
- [`woocommerce.md`](woocommerce.md) — the WooCommerce add-on preset
- [`docs/README.md`](README.md) — all presets
