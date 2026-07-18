# W3 Total Cache + cache-turbo

_Last researched: 2026-07-18_

W3 Total Cache (`w3-total-cache`, 900k+ installs) is the most feature-heavy WP
caching plugin — page cache, minify, object cache, database cache, browser
cache, CDN, all in one settings screen. This is **not a new backend preset**:
it's an interop doc, because W3TC is the plugin most likely to already own
every cache layer on the box, including Redis. Use the `wordpress` preset
([wordpress.md](wordpress.md)) unchanged; this page is about turning off the
one W3TC module that fights it.

- [The short version](#the-short-version)
- [Cookies: bypass vs key](#cookies-bypass-vs-key)
- [Redis: keep them on separate DBs](#redis-keep-them-on-separate-dbs)
- [Vhost: page cache + Redis L2](#vhost-page-cache--redis-l2)
- [Purging on publish](#purging-on-publish)
- [Gotchas](#gotchas)
- [PHP settings / gotchas](#php-settings--gotchas)

## The short version

**Disable W3TC's Page Cache module. Keep everything else.**

Performance → General Settings → uncheck **Page Cache**. Leave Object Cache,
Database Cache, Minify, Browser Cache, and CDN enabled if you were already
using them.

Why the split: cache-turbo and W3TC's page cache both do the same job (serve
whole rendered HTML for anonymous visitors without hitting PHP), so running
both is pure redundancy at best and a correctness trap at worst — two full-page
caches independently deciding what's safe to store means two independently
wrong answers are possible. Object Cache and Database Cache are a different
layer entirely: they speed up **PHP itself** (the origin cache-turbo falls
through to on a MISS), exactly like WordPress's own object-cache drop-in
described in [wordpress.md](wordpress.md#wordpresss-own-object-cache--a-different-thing).
Nothing about that layer conflicts with a page cache in front of it — keep it.

On nginx, W3TC does something the Apache-only caching plugins can't: when it
detects nginx (`Util_Environment::is_nginx()`), its Page Cache module **writes a
real nginx config fragment** — by default `<site-root>/nginx.conf`, or a path you
set under Performance → General Settings (e.g. `/etc/nginx/conf.d/w3tc.conf`) —
that you then `include` in your `server` block. What that fragment does depends on
the page-cache engine (verified against W3TC 2.10.2, `PgCache_Environment.php`):

| Page cache method (engine) | On nginx |
|---|---|
| Disk: Basic (`file`) | Functions — PHP still runs on every request (via the `advanced-cache.php` drop-in) to check for a cached file and serve it, then exits early. Not free (PHP bootstraps every hit), just cheaper than a full render. No nginx fragment involved. |
| Disk: Enhanced (`file_generic`) | **A genuine zero-PHP front cache — this is the double-cache.** The generated fragment ends in `rewrite .* "<cache-file>" last;`, serving the pre-rendered `.html` / `.html_gzip` / `.html_br` straight from disk with no PHP at all — the nginx equivalent of the Apache `mod_rewrite` path. It works only if you `include` W3TC's `nginx.conf`; W3TC's own `verify_file_generic_rewrite_working()` nags when you haven't. Once included, it front-caches exactly like cache-turbo. |
| Memcached (`nginx_memcached`) | **Also a zero-PHP front cache.** The fragment emits a `location` block with `set $memcached_key …; memcached_pass …;`, serving the page from nginx's own `memcached` module — no PHP. Same double-cache hazard as Disk: Enhanced. |
| Redis / Memcached (PHP engine) | PHP runs (via `advanced-cache.php`) and looks the page up in Redis/Memcached instead of on disk. Cheaper than a full render, but still a per-request PHP bootstrap — not a front cache, no nginx fragment. |
| Opcache | Stores compiled PHP opcode, not page HTML — unrelated to page caching regardless of web server. |

So on nginx W3TC has **two** engines (Disk: Enhanced and nginx+Memcached) that
genuinely serve whole pages before PHP — precisely cache-turbo's job. Running
either in the same `server` block as cache-turbo is a true double front-cache: two
independent layers deciding what's safe to store, two ways to be wrong. The
remaining engines still cost a PHP bootstrap per request. Either way the
recommendation is the same — turn the module off and let cache-turbo own the nginx
front.

## Cookies: bypass vs key

W3TC's own page-cache "don't cache for logged-in users" logic rides WordPress
core's `wordpress_logged_in_*` cookie — same signal the `wordpress` preset
already bypasses on. **Nothing new to add for identity.**

| Cookie | Treatment | Why |
|---|---|---|
| `wordpress_logged_in_*` | **bypass** (preset, auto) | same as stock WP — see [wordpress.md](wordpress.md#cookies-bypass-vs-key) |
| `wp-postpass_*` | **bypass** (preset, auto) | password-protected post reader |
| `comment_author_*` | **bypass** (preset, auto) | commenter personalization |
| `w3tc_referrer` | **key (variant) — only if you use Referrer / User-Agent Groups** | Confirmed in source (W3TC 2.10.2, `Mobile_Referrer.php`, `W3TC_REFERRER_COOKIE_NAME`). Not an identity or session cookie: W3TC sets it only when a Referrer Group or User-Agent Group is enabled, to store the visitor's referrer so the cached *variant* stays consistent across page views. It carries no login signal. If you run those groups it's the cookie W3TC varies caching on — mirror it into `cache_turbo_key_cookie` so cache-turbo varies the same way; if you don't use the groups it is never set. |
| `w3tc_logged_out` | **bypass — optional, transient** | Confirmed in source (`PgCache_Plugin.php` sets it in `on_logout()`, clears it in `on_login()`; `PgCache_Environment.php` adds it to `$reject_cookies` unconditionally). It is a deliberate, short-lived signal set for the one request right after logout, so W3TC's own page cache is bypassed during the transition (`wordpress_logged_in_*` is already gone by then). Not "safe to ignore" — it's a real bypass cookie in W3TC's logic. Low-stakes for cache-turbo (transient, and an anonymous cache hit is usually fine), but adding it to `cache_turbo_bypass` is correct belt-and-braces if you want the just-logged-out request to always render fresh. |

No new *key* cookies either — W3TC doesn't add a presentation/variant cookie
of its own the way a multilingual plugin would. If you also run a W3TC Cookie
Groups configuration to vary caching by some custom cookie, mirror that
choice into `cache_turbo_key_cookie` yourself; it's a site-specific rule the
plugin can't tell us in general.

## Redis: keep them on separate DBs

**This is the one that bites.** W3TC users are, more than any other WP
caching plugin's users, already running Redis for Object Cache and/or
Database Cache before cache-turbo ever enters the picture. Same rule as
[xenforo.md's Redis section](xenforo.md#xenforos-own-object-cache-redis--a-different-thing):
**cache-turbo's L2 and W3TC's Redis config must use different DB numbers
and/or prefixes on the same Redis instance.**

W3TC's Object/DB Cache Redis settings live in Performance → General
Settings → Object Cache / Database Cache (or `wp-config.php` for some
setups), independent of nginx:

```
Object Cache Method:   Redis
Redis hostname:port:   10.0.0.5:6379
Redis database:        1        <-- NOT the DB cache-turbo's L2 uses
```

cache-turbo's L2 gets its own DB:

```nginx
cache_turbo_redis redis://10.0.0.5:6379/0 prefix=w3tc-ct: timeout=250ms
                  keepalive=32 keepalive_timeout=60s;
```

If both point at the same DB, `curl -X POST '.../_cache?all=1'` (cache-turbo's
own purge) risks colliding key namespaces with W3TC's object-cache keys —
worst case, a `FLUSHDB`-style operation on either side takes out both layers.
Distinct DB numbers make that structurally impossible; a distinct `prefix=`
on top is cheap insurance if you're ever unsure which DB W3TC actually landed
on (its settings UI has moved around across versions).

## Vhost: page cache + Redis L2

Standard `wordpress` preset, with the L2 wired up — reuse this as-is if
you're migrating a W3TC-with-Redis install to cache-turbo.

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    # Shared L2 — DB 0, distinct from W3TC's Object/DB Cache (DB 1 above).
    cache_turbo_redis redis://10.0.0.5:6379/0 prefix=w3tc-ct: timeout=250ms
                      keepalive=32 keepalive_timeout=60s;

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
            cache_turbo_preset        balanced;   # SWR: serve stale while one refresh runs

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

## Purging on publish

W3TC hooks WordPress's `save_post` / `transition_post_status` internally and
calls its own `w3tc_flush_post()` (single post) or `w3tc_flush_all()` (full
flush) to purge **its own** page cache. Turning off W3TC's Page Cache module
does not disable those hooks firing for its *other* modules (minify, object
cache still purge appropriately) — it just means there's no page cache left
for them to act on.

Wire cache-turbo's own purge from the same `save_post` event, independently —
the two plugins' flush hooks don't talk to each other:

```php
// mu-plugin, alongside any existing W3TC purge hooks
add_action( 'save_post', function ( $post_id ) {
    if ( wp_is_post_revision( $post_id ) ) return;
    $url = get_permalink( $post_id );
    if ( ! $url ) return;
    wp_remote_post( 'http://127.0.0.1/_cache?key=' . rawurlencode( wp_make_link_relative( $url ) ) );
}, 20 );
```

Same caveat as [wordpress.md](wordpress.md#purging-on-publish): a new post
also changes the front page, category archives, and feeds — purge those too,
or accept the TTL on them.

## Gotchas

- **Turn off Page Cache, not the whole plugin.** Deactivating W3TC entirely
  also kills Minify, Object Cache, Database Cache, Browser Cache and CDN
  rewriting — all genuinely useful and orthogonal to page caching. Disable
  only the Page Cache module in Performance → General Settings.
- **Leaving W3TC's Page Cache ON wastes work for nothing.** Even in
  Memcached/Redis mode, every cache-turbo MISS that falls through to PHP
  still pays W3TC's own page-cache lookup/miss overhead on the way in — a
  second cache check that can never win a race it's disabled from winning
  (cache-turbo already decided this wasn't a hit). Pure tax, zero benefit.
- **Disk: Enhanced writes an nginx fragment + `WP_CACHE` — clean both up when
  you disable it.** On an nginx-detected install W3TC does *not* touch
  `.htaccess`; it writes its page-cache rules to `<site-root>/nginx.conf` (or the
  path you set) and toggles `define('WP_CACHE', true)` plus the
  `advanced-cache.php` drop-in. If you `include` that fragment it front-caches
  (the double-cache above); if you don't, it silently serves nothing and W3TC
  nags. Turning Page Cache off from the W3TC UI removes the `advanced-cache.php`
  drop-in and the `WP_CACHE` define — but the `include` line you added by hand to
  your `server` block is yours to delete, so the next person auditing the vhost
  doesn't find dead W3TC rewrite rules next to cache-turbo's.
- **Minify and Fragment Cache are unaffected — keep them enabled.** Both
  operate on PHP-rendered output before/independent of whether a page cache
  stores the result; orthogonal to cache-turbo either way.
- **Object Cache / DB Cache Redis and cache-turbo's L2 Redis must not share a
  DB number.** See the [Redis section](#redis-keep-them-on-separate-dbs)
  above — this is the mistake most likely to actually happen on a W3TC box,
  because the Redis instance is usually already there.
- **`Set-Cookie` responses are never stored** by cache-turbo regardless of
  what W3TC does — that floor is unconditional, same as every other preset.

## PHP settings / gotchas

W3TC-specific notes for the PHP origin cache-turbo falls through to on a MISS.
All plugin-specific; generic PHP-FPM / opcache tuning lives in
[wordpress.md](wordpress.md).

- **The nginx page-cache fragment double-caches — the one that matters.** W3TC's
  Disk: Enhanced (`file_generic`) and nginx+Memcached (`nginx_memcached`) engines
  write a real nginx fragment that serves whole pages before PHP (see the table
  above). If it's `include`d in the same `server` block as cache-turbo you have
  two front caches stacked. Disable Page Cache; keep the fragment out of the
  vhost.
- **Object Cache / DB Cache drop-ins are the good half — keep them.** W3TC
  installs `wp-content/object-cache.php` (object cache) and `wp-content/db.php`
  (database cache) drop-ins that back onto Redis or Memcached. They cache *inside*
  PHP, so they only pay off on a cache-turbo MISS — exactly where you want the
  origin faster. They never front-cache and never conflict with cache-turbo. Just
  keep their Redis on a different DB/prefix than cache-turbo's L2 (see the
  [Redis section](#redis-keep-them-on-separate-dbs)).
- **`advanced-cache.php` is the page-cache drop-in — it goes away with Page
  Cache.** W3TC's `advanced-cache.php` (loaded by `wp-settings.php` before the
  plugin, gated on `define('WP_CACHE', true)`) is what makes the Disk: Basic and
  PHP-Redis/Memcached engines run their lookup on every request. Turning Page
  Cache off from the UI removes the drop-in and the `WP_CACHE` define; don't leave
  a stale `advanced-cache.php` behind — W3TC warns if a foreign one is present.
- **Minify runs in PHP on a MISS — orthogonal, keep it.** W3TC Minify
  rewrites/combines CSS/JS in the rendered output before it leaves PHP. It costs a
  little origin CPU per full render but nothing at the nginx layer, and cache-turbo
  simply caches the already-minified HTML. No conflict.
- **Opcache is opcode, not pages.** W3TC's "Opcache" option manages PHP's opcode
  cache (compiled bytecode). It speeds every PHP bootstrap and is unrelated to page
  caching — keep it on; it helps the origin cache-turbo falls through to.

## See also

- [wordpress.md](wordpress.md) — the baseline preset this doc builds on;
  cookie table, vhost syntax, and purge pattern are unchanged here.
- [woocommerce.md](woocommerce.md) — if the site also runs WooCommerce,
  stack `cache_turbo_backend wordpress woocommerce;`.
- [xenforo.md — XenForo's own object cache](xenforo.md#xenforos-own-object-cache-redis--a-different-thing) —
  the same Redis-DB-separation pattern documented for a different CMS.
- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend) —
  the preset table and how `cache_turbo_backend` composes.
- [README — Redis L2](../README.md#redis-l2-shared-cache) — full L2 DSN
  syntax, TLS, keepalive.
