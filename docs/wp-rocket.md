# WP Rocket + cache-turbo

_Last researched: 2026-07-18_

WP Rocket is a premium (no wordpress.org listing), PHP/htaccess-based WordPress
caching plugin — page cache, minify, lazy-load, CDN rewriting, database cleanup,
preloading. This is **not** a `cache_turbo_backend` preset — there is no
`wp-rocket` value and there will not be one. This doc is an **interop** guide:
run cache-turbo for the HTML page cache, keep WP Rocket for everything else it
does well, and configure the two so they don't fight.

- [The short version](#the-short-version)
- [Why WP Rocket's own page cache barely applies here](#why-wp-rockets-own-page-cache-barely-applies-here)
- [Cookies: nothing extra beyond the wordpress preset](#cookies-nothing-extra-beyond-the-wordpress-preset)
- [Query strings WP Rocket already ignores](#query-strings-wp-rocket-already-ignores)
- [Vhost: cache-turbo owns the page cache](#vhost-cache-turbo-owns-the-page-cache)
- [Purging on publish](#purging-on-publish)
- [Gotchas](#gotchas)
- [PHP settings / gotchas](#php-settings--gotchas)
- [See also](#see-also)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend wordpress;
```

In WP Rocket: **Settings → Cache → uncheck "Enable caching for mobile devices"
is irrelevant, but uncheck/disable the plugin's own page-cache feature** (WP
Rocket's Basic Cache Files, the thing that writes to
`wp-content/cache/wp-rocket/`). Keep everything else on: minification, combine,
lazy-load, CDN rewriting, database optimization, preloading, "Remove Unused
CSS", etc. — those are all real, independent wins that don't overlap with
page caching.

Why: two independent full-page caches at two different layers — WP Rocket's
PHP-file-based cache and cache-turbo's nginx-shm cache — invites double-caching
and stale-serve races (which one purges first? which one's TTL wins? which
one's stale copy does a visitor land on if the other purges but this one
hasn't?), and buys nothing, because **cache-turbo is strictly faster**: it
serves a HIT before PHP even boots, whereas WP Rocket's fastest path (the
Apache/LiteSpeed `.htaccess` rewrite, or a manually-installed nginx helper
config — see below) still needs the web server to route straight to a static
file, and on a stock nginx box without that helper installed, WP Rocket's
cache is checked *from inside PHP*, i.e. after the origin already booted.
Running both page caches gains you nothing cache-turbo doesn't already do,
and adds a second cache to reason about, key correctly, and purge in sync.

## Why WP Rocket's own page cache barely applies here

WP Rocket's page-cache mechanism writes static HTML to
`wp-content/cache/wp-rocket/<host>/...` and serves it two ways:

1. **Apache / LiteSpeed**: `.htaccess` rewrite rules WP Rocket writes on
   activation route a cache HIT straight to the static file, bypassing PHP
   entirely. This is WP Rocket's fast path, and it's Apache/LiteSpeed-specific.
2. **NGINX**: WP Rocket [documents itself as compatible with
   NGINX](https://docs.wp-rocket.me/article/71-which-web-servers-is-wp-rocket-compatible-with)
   but ships no `.htaccess`-equivalent auto-config for it — nginx has no
   per-directory config file to drop rules into. To get the same
   bypass-PHP-entirely behavior on nginx you must **manually install** a
   third-party nginx snippet (the commonly referenced one is
   [`rocket-nginx`](https://github.com/SatelliteWP/rocket-nginx) — originally by
   Maxime Jobin, now maintained under the SatelliteWP org, *not* an official WP
   Rocket deliverable, though WP Rocket run it on their own site) that
   `try_files`-checks the cache directory ahead of `index.php`.

**Without that manual nginx snippet installed — the default on a stock
cache-turbo vhost — WP Rocket's page cache still runs, but every request goes
through nginx → PHP-FPM → WordPress bootstrap → WP Rocket's own PHP-level
check of its cache file**, per the plugin's own troubleshooting docs: "cache is
served by PHP files" when the web-server-level rewrite isn't in place ([Pages
are not cached or optimizations are not
working](https://docs.wp-rocket.me/article/99-pages-not-cached-or-optimizations-not-working)).
That's strictly slower than cache-turbo's MISS path (which also goes through
PHP) and *far* slower than cache-turbo's HIT path (which never does). There is
no scenario on a cache-turbo vhost where installing the `rocket-nginx` helper
on top makes anything faster — cache-turbo already serves the HIT before
nginx would even reach the `try_files` check `rocket-nginx` adds. Recommended
split: **disable WP Rocket's page cache, don't install `rocket-nginx`, let
cache-turbo own the HTML.**

## Cookies: nothing extra beyond the wordpress preset

WP Rocket does not define its own login/session cookie. It defers entirely to
WordPress core's own auth state (`is_user_logged_in()`) and to WP core's
`wordpress_logged_in_*` cookie — the same one the `wordpress` preset already
bypasses on (see [`wordpress.md`](wordpress.md#cookies-bypass-vs-key)). Nothing
to add.

WP Rocket does ship an optional **User Cache** feature — when enabled, *WP
Rocket's own* file cache forks a separate cached file per logged-in user
(rather than serving one static page to everyone). That's an internal detail
of WP Rocket's PHP-cache layer; it's moot once you disable that layer per the
short version above. If you keep WP Rocket's page cache running for some
reason, its own docs note you should list any plugin-added logged-in/out
cookie in its **"Never Cache Cookies"** setting — same idea as
`cache_turbo_no_store`, different layer.

| Cookie | Treatment | Why |
|---|---|---|
| `wordpress_logged_in_*` | **bypass** (from `wordpress` preset) | the only identity signal WP Rocket relies on too |
| WP Rocket's own login cookie | **none exists** | confirmed — WP Rocket authenticates via WP core state, not a cookie of its own |

## Query strings WP Rocket already ignores

WP Rocket ignores a fixed default list of tracking/marketing query params for
*its own* cache-key purposes (same file served regardless of the param's
value): `utm_*` (source/medium/campaign/etc.), `gclid`, `fbclid`,
`fb_action_ids`, `fb_action_types`, `fb_source`, `_ga`, `age-verified`,
`ao_noptimize`, `usqp`, `cn-reloaded` — customizable via the
`rocket_cache_ignored_parameters` PHP filter
([Caching query strings](https://docs.wp-rocket.me/article/971-caching-query-strings),
[Customize query string
caching](https://docs.wp-rocket.me/article/1281-customize-query-string-caching)).

cache-turbo's `$cache_turbo_normalized_args` already strips the standard
tracking-param set independently at the nginx layer (see
[README — The cache key](../README.md#the-cache-key)) — the two lists overlap
in intent (drop marketing params from the key) but are enforced at different
layers and don't need to be kept in lockstep; cache-turbo's normalization runs
regardless of what WP Rocket's PHP filter says, since cache-turbo (once you've
disabled WP Rocket's page cache per above) is the only layer actually deciding
cache keys for HTML.

WP Rocket also ships a **`?nowprocket`** bypass query arg ([Bypass WP Rocket's
caching and
optimizations](https://docs.wp-rocket.me/article/1285-bypass-wp-rockets-caching-and-optimizations))
for skipping its own cache/minify pipeline — this is WP Rocket-internal and has
no cache-turbo equivalent needed; it doesn't affect nginx-layer caching at all
since cache-turbo doesn't recognize or need to recognize that param.

## Vhost: cache-turbo owns the page cache

Same structure as the stock WordPress vhost in
[`wordpress.md`](wordpress.md#vhost-page-cache-only) — WP Rocket needs nothing
extra in the vhost once its own page-cache feature is switched off in its
admin settings:

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

            # Belt and braces on top of the preset — same as stock WordPress.
            cache_turbo_no_store      $wp_logged_in;

            include                   fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_pass  unix:/run/php/php-fpm.sock;
        }

        # Minified/combined CSS+JS and WP Rocket's CDN-rewritten assets are
        # still just static files — let nginx serve them directly, same as
        # any other WordPress asset. No cache-turbo interaction.
        location ~* \.(css|js|png|jpe?g|gif|webp|svg|woff2?)$ {
            cache_turbo off;
            expires 30d;
            access_log off;
        }

        # Do NOT add a rocket-nginx style try_files-into-wp-content/cache/wp-rocket/
        # block here (see "Why WP Rocket's own page cache barely applies" above)
        # — it would race cache-turbo's own cache for the same URL space.

        location = /_cache {
            cache_turbo_admin on;
            allow 127.0.0.1;
            deny  all;
        }
    }
}
```

## Purging on publish

WP Rocket purges *its own* file cache on publish/update via its internal
functions — `rocket_clean_post()` (single post + related archives/feeds) and
`rocket_clean_domain()` (whole cache, e.g. after a theme/plugin change), wired
internally to `save_post` / `transition_post_status` and to the
`after_rocket_clean_domain` action when a full clear runs
([How to programmatically clear the cache and
optimizations](https://docs.wp-rocket.me/article/1801-how-to-programmatically-clear-the-cache-and-optimizations)).
**Unverified/community-reported:** some third-party integration guides
reference a `rocket_purge_cache` action fired on cache-clear events — this
exact hook name is not present in WP Rocket's own documented API; treat it as
unconfirmed and don't build automation on it without checking the installed
version's source (`inc/common/purge.php`).

None of that touches cache-turbo. With WP Rocket's own page cache disabled per
the short version, its purge functions are firing against an empty/inert
cache dir — harmless, but also *not* purging the cache that matters. Hook
cache-turbo's purge into the same WordPress publish events instead (or in
addition, from the same mu-plugin):

```php
<?php
// mu-plugins/cache-turbo-purge.php
add_action( 'transition_post_status', function ( $new, $old, $post ) {
    if ( $new !== 'publish' && $old !== 'publish' ) {
        return;
    }
    // The admin endpoint hashes ?key= verbatim -- it must equal the full
    // cache key (host + uri + normalized args), not just the path.
    $permalink = get_permalink( $post );
    $key = wp_parse_url( $permalink, PHP_URL_HOST ) . wp_parse_url( $permalink, PHP_URL_PATH );
    wp_remote_post( 'http://127.0.0.1/_cache?key=' . rawurlencode( $key ) );
    // Also purge the front page / relevant archive if this post appears there.
    $front_key = wp_parse_url( home_url( '/' ), PHP_URL_HOST ) . '/';
    wp_remote_post( 'http://127.0.0.1/_cache?key=' . rawurlencode( $front_key ) );
}, 10, 3 );

// Optional: piggyback on WP Rocket's own full-clear event so "Clear cache"
// in wp-admin also flushes cache-turbo's zone.
add_action( 'after_rocket_clean_domain', function () {
    wp_remote_post( 'http://127.0.0.1/_cache?all=1' );
} );
```

Same key mechanics as [`wordpress.md` → Purging on
publish](wordpress.md#purging-on-publish): a 60s TTL means this is a
nice-to-have for instant visibility, not a correctness requirement.

## Gotchas

> **Subdirectory installs.** This preset's URI rules are root-relative literals
> matched from byte 0 of `r->uri`, so an install mounted under a subdirectory
> (`/shop/`, `/forum/`, …) matches **none** of them — the admin surface
> included. Declare the mount with `cache_turbo_backend_prefix /forum/;` and the
> preset URI tier is compared against the rebased path. Scoping the nginx
> `location` does **not** substitute: it routes requests, it does not rewrite
> `r->uri`. See [frameworks.md](frameworks.md).

- **If you insist on running WP Rocket's page cache alongside cache-turbo
  anyway** (against this doc's recommendation) — do not also install the
  `rocket-nginx` helper snippet. That snippet's `try_files` would intercept
  requests *before* cache-turbo's `location ~ \.php$` block ever sees them,
  which means cache-turbo stops being consulted at all for any URL WP Rocket
  already has a static file for — your `X-Cache-Turbo` header and admin
  endpoint stats go dark for exactly the traffic you care about, and you now
  have two independently-TTL'd, independently-purged copies of every page
  with no way to know which one a given visitor received. Recommended against
  plainly: don't do this.
- **WP Rocket's minify/combine cache** (`wp-content/cache/min/`) is a
  different, unrelated cache (CSS/JS assets, not HTML pages) — leave it
  enabled, it has nothing to do with cache-turbo.
- **Preload.** WP Rocket's own sitemap-based preloader (which pre-warms *its*
  page cache) is pointless once its page cache is disabled — turn it off too,
  it's wasted requests. Preloading cache-turbo's shm cache is a separate
  concern; see the module README's cache-warming notes if you need that.
- **Database optimization / cleanup features** (revisions, transients,
  trashed comments) are entirely orthogonal to either page cache — keep them
  on regardless of what you do with the caching layers.
- **CDN rewriting.** If WP Rocket rewrites asset URLs to a CDN host, that's
  independent of cache-turbo (which only ever sees the origin's own HTML
  responses) — no interaction, no config needed on the cache-turbo side.

## PHP settings / gotchas

WP-Rocket-specific PHP-layer notes (everything here is about WP Rocket's own PHP
footprint, not cache-turbo's):

- **Its page cache is a PHP drop-in, not an htaccess/nginx rule.** The cache
  *logic* lives in the `advanced-cache.php` WordPress drop-in (WP Rocket writes
  it to `wp-content/advanced-cache.php` on activation), which WordPress executes
  very early — before the full core/theme/plugin bootstrap — **only if the
  `WP_CACHE` constant is `true`** in `wp-config.php` (WP Rocket sets
  `define( 'WP_CACHE', true );` on activation). The `.htaccess` rewrite (Apache)
  or the `rocket-nginx` config is *only* an optional faster serve-path that lets
  the web server return the cached HTML without touching PHP at all; it is not
  where the cache is implemented. On a stock nginx box with neither in place,
  every hit is served by `advanced-cache.php` from inside PHP-FPM — early in the
  request, but still after PHP has started. That is why cache-turbo (which serves
  its HIT before PHP forks at all) wins, and why disabling WP Rocket's page cache
  is the right call here. ([Page caching](https://docs.wp-rocket.me/article/1528-page-caching),
  [SpinupWP: cache plugins + nginx](https://spinupwp.com/blog/wordpress-page-cache-plugins-nginx/).)
- **If you disable WP Rocket's page cache, leave `WP_CACHE`/`advanced-cache.php`
  alone.** Turning the feature off in WP Rocket's own settings is enough — don't
  hand-edit `wp-config.php` to remove `WP_CACHE` or delete the drop-in, as WP
  Rocket manages both and will regenerate/complain. An orphaned or stale
  `advanced-cache.php` (e.g. left by a previously-removed cache plugin) can cause
  a white screen or serve nothing; if you see that, let WP Rocket rewrite its own
  drop-in rather than editing it by hand.
- **Preload crawler is real PHP-FPM load.** WP Rocket's sitemap-based preloader
  runs as an Action-Scheduler background process (WP-Cron or system cron),
  crawling URLs at a default ~500ms interval and allowed up to ~90% of PHP
  memory. On a large site it can pile up PHP-FPM workers and spike CPU — a
  documented failure mode on big WooCommerce catalogs. Since it only pre-warms
  *WP Rocket's* page cache, it is pure wasted origin load once that cache is
  disabled per the short version; turn it off. ([Preload cache](https://docs.wp-rocket.me/article/8-preload-cache),
  [High CPU usage](https://docs.wp-rocket.me/article/48-high-cpu-usage).)
- **WP Rocket has no object cache of its own.** It is a page/asset optimizer;
  persistent object caching (Redis/Memcached) is a *separate* `object-cache.php`
  drop-in from another plugin (e.g. Redis Object Cache), not a WP Rocket add-on.
  The two do not conflict — run object caching if you want a faster MISS path
  (cache-turbo's MISS still boots PHP+WordPress, so a warm object cache helps
  there) — but don't expect WP Rocket to provide it.
  ([Redis and object caching](https://docs.wp-rocket.me/article/1359-redis-object-caching).)
- **OPcache.** Orthogonal to both page caches and always worth having on for the
  PHP that cache-turbo's MISS path (and WP Rocket's own `advanced-cache.php`
  drop-in) executes. WP Rocket does not manage OPcache; configure it in
  `php.ini`/PHP-FPM as usual. Note WP Rocket's *minification* cache
  (`wp-content/cache/min/`) is unrelated to OPcache — one is CSS/JS on disk, the
  other is compiled PHP bytecode.

## See also

- [`wordpress.md`](wordpress.md) — the base WordPress preset this doc builds on
- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [README — The cache key](../README.md#the-cache-key)
- [`docs/README.md`](README.md) — all presets
