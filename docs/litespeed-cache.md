# LiteSpeed Cache (WordPress plugin) + cache-turbo

_Last researched: 2026-07-18_

Interop notes for a site running **both** cache-turbo at the nginx layer and the
**LiteSpeed Cache** plugin (slug `litespeed-cache`, ~7M+ active installs — the
largest WP caching plugin) inside WordPress. There is **no `litespeed-cache`
preset keyword** — this is not a `cache_turbo_backend` value. You keep
`cache_turbo_backend wordpress;` as the base and layer a handful of extra
directives on top for this plugin's quirks.

- [Read this first: the plugin's own page cache is dormant here](#read-this-first-the-plugins-own-page-cache-is-dormant-here)
- [What actually still matters from the plugin](#what-actually-still-matters-from-the-plugin)
- [Cookies / headers: bypass vs ignore](#cookies--headers-bypass-vs-ignore)
- [Vhost: wordpress preset + LiteSpeed Cache extras](#vhost-wordpress-preset--litespeed-cache-extras)
- [Object cache: Redis DB separation](#object-cache-redis-db-separation)
- [Purging on publish](#purging-on-publish)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)
- [PHP settings / gotchas](#php-settings--gotchas)
- [See also](#see-also)

## Read this first: the plugin's own page cache is dormant here

**LSCache — the plugin's actual full-page cache — is a server-level feature of
the LiteSpeed web server** (or its proprietary nginx module, `ngx_lscache`,
shipped only by LiteSpeed's own nginx build). The plugin's WordPress-side code
talks to that engine over response headers (`X-LiteSpeed-Cache-Control`,
`X-LiteSpeed-Tag`, etc.); it does not implement a cache of its own in PHP.

**On stock/vanilla nginx — which is what cache-turbo runs on — there is no
LSCache engine to talk to, and the plugin knows it: those headers are not even
emitted.** Verified against plugin **v7.8.1** source: `litespeed-cache.php`
sniffs the server at bootstrap (`HTTP_X_LSCACHE`, `LSWS_EDITION`,
`SERVER_SOFTWARE`) and sets `LITESPEED_SERVER_TYPE` — on plain nginx that is
`'NONE'`, so `LITESPEED_ALLOWED` and then `LITESPEED_ON` are never defined.
Every `X-LiteSpeed-*` response header in `core.cls.php` (Cache-Control, Purge,
Vary, Tag) is wrapped in `if ( defined( 'LITESPEED_ON' ) )`, so on this stack
none of them go out at all (the only exception is the admin-only `?LSCWP_CTRL`
debug query string). **The plugin's page-cache is inactive.** WordPress.org's
own plugin FAQ agrees: caching features require a LiteSpeed server; on
Apache/nginx "none of the plugin's caching functionality will be available" —
the plugin still installs and runs, but only its **optimizer** features do
anything: CSS/JS minify and combine, image optimization, lazy load, CDN
integration, database optimization, and (importantly) the **object cache**
module (Redis/Memcached).

**Practical upshot: cache-turbo is the page cache on this stack, full stop.**
You are not double-caching HTML — the plugin isn't caching HTML at all here.
Configure it as an optimizer-only tool (Page Optimization / Image / DB tabs)
and turn its Cache tab into a no-op, or leave it on — it's inert either way as
long as nginx isn't the LiteSpeed fork. Don't waste time chasing "why doesn't
LSCache show hits" on this stack; it can't.

> If you ever migrate the origin to actual LiteSpeed/OpenLiteSpeed with
> `ngx_lscache`, this changes — you'd then have two real HTML caches (LSCache
> at the web-server layer, cache-turbo in front of it) and would need to pick
> one. Out of scope for this doc; if that happens, disable one of them rather
> than running both.

## What actually still matters from the plugin

Even with page-caching inert, a few plugin behaviors are worth knowing about
because they touch the same signals cache-turbo cares about:

- **Vary cookie (`_lscache_vary` / renamed "Login Cookie").** LSCache's vary
  mechanism keys the *LiteSpeed engine's* cache on a cookie that signals
  logged-in state, distinct from `wordpress_logged_in_*`. **Verified in v7.8.1:
  the plugin DOES set this cookie on stock nginx** — `Vary::after_user_init()`
  is wired unconditionally (it is not gated on `LITESPEED_ON`), hooking WP-core
  `set_logged_in_cookie` → `add_logged_in` → `_cookie()`, which calls
  `setcookie('_lscache_vary', …)` on login, plus `set_comment_cookies` for
  commenters. So the cookie is real here even though the engine that would
  consume it is absent. It is not a leak vector on its own (`wordpress_logged_in_*`
  and `comment_author_*` — both already bypassed by the `wordpress` preset —
  cover the same users), but bypassing `_lscache_vary` too is now a
  **confirmed-useful** belt-and-braces measure rather than mere insurance,
  especially if you enable the plugin's **Guest Mode** (off by default), which
  makes `update_guest_vary` set the cookie for anonymous visitors as well. The
  name defaults to `_lscache_vary` but can be overridden by the `LSCACHE_VARY_COOKIE`
  server var or the "Login Cookie" setting — match your bypass to whatever is
  configured.
- **`X-LiteSpeed-Cache-Control` response header.** On stock nginx this header
  is **not emitted** (v7.8.1: gated behind `defined( 'LITESPEED_ON' )` in
  `core.cls.php`, which is never true here). Even if it were, it is not
  `Cache-Control`, so cache_turbo_cache_control (`honor`/`respect`) would never
  see it — there is **no conflict** either way. No action needed. (Same story
  for `X-LiteSpeed-Tag` and `X-LiteSpeed-Vary`: computed in PHP but suppressed
  before send on a non-LiteSpeed server.)
- **Object cache (Redis/Memcached).** This module works standalone on any web
  server — it's a WordPress object-cache drop-in, not tied to the LSCache
  engine. If pointed at the same Redis instance as `cache_turbo_redis`, see
  [Object cache: Redis DB separation](#object-cache-redis-db-separation) below.
- **ESI (Edge Side Includes).** LSCache's ESI blocks are stitched by the
  LiteSpeed engine at serve time. With the engine absent, the ESI/vary headers
  that would drive them are suppressed along with every other `X-LiteSpeed-*`
  header (same `LITESPEED_ON` gate), so ESI is inert on stock nginx — not a
  correctness hazard. Confirmed at the header-emission layer against v7.8.1;
  not exercised against a live LSCache-ESI-enabled instance for this doc.

## Cookies / headers: bypass vs ignore

| Cookie / header | Treatment | Why |
|---|---|---|
| `wordpress_logged_in_*` | **bypass** (already in `wordpress` preset) | the real, confirmed WP-core login signal — unaffected by this plugin |
| `wp-postpass_*` | **bypass** (already in `wordpress` preset) | password-protected post reader |
| `comment_author_*` | **bypass** (already in `wordpress` preset) | personalised comment form |
| `_lscache_vary` (or custom "Login Cookie" name) | **bypass** (extra, belt-and-braces) | login/commenter vary cookie; **v7.8.1-confirmed the plugin sets it even on stock nginx** — see bullet above. Redundant with `wordpress_logged_in_*`/`comment_author_*` unless Guest Mode is on, but cheap and safe |
| `X-LiteSpeed-Cache-Control` (response header) | **ignore** | not emitted on stock nginx (gated on `LITESPEED_ON`); no interaction with `cache_turbo_cache_control` |
| `X-LiteSpeed-Tag` (response header) | **ignore** | LSCache-engine purge-tag header; also suppressed on stock nginx, meaningless without the engine |

Nothing here belongs in the cache **key** — this plugin does not introduce a
new public "variant" (theme/language) the way a multi-style forum plugin
would; it's login-state and optimizer machinery only.

## Vhost: wordpress preset + LiteSpeed Cache extras

Same shape as [`wordpress.md`](wordpress.md)'s single vhost, with the plugin's
extra bypass cookie layered on via `cache_turbo_bypass` (the preset stays
`wordpress` — this is additive, not a replacement):

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
            cache_turbo_backend       wordpress;   # base preset — unchanged

            cache_turbo_valid         60s;
            cache_turbo_valid         404 410 1m;
            cache_turbo_preset        balanced;

            # Belt and braces on top of the preset (same pattern as
            # wordpress.md's own cache_turbo_no_store line):
            cache_turbo_no_store      $cookie_wordpress_logged_in_;

            # LiteSpeed Cache plugin extra: bypass its own login-vary cookie
            # too. v7.8.1-confirmed the plugin sets _lscache_vary on login even
            # with the LSCache engine absent (belt-and-braces on top of the
            # wordpress_logged_in_ bypass; also covers Guest Mode if enabled).
            cache_turbo_bypass        $cookie__lscache_vary;

            include                   fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_pass  unix:/run/php/php-fpm.sock;
        }

        location ~* \.(css|js|png|jpe?g|gif|webp|svg|woff2?)$ {
            cache_turbo off;
            expires 30d;
            access_log off;
        }

        # Admin endpoint — cache-turbo's OWN purge/stats, NOT the plugin's.
        location = /_cache {
            cache_turbo_admin on;
            cache_turbo_purge on;
            allow 127.0.0.1;
            deny  all;
        }
    }
}
```

If you renamed the plugin's "Login Cookie" away from the `_lscache_vary`
default (Cache > Advanced) or set a `LSCACHE_VARY_COOKIE` server var, match
`cache_turbo_bypass` to whatever name you picked. Keep the line: v7.8.1 sets
this cookie on every login regardless of server, so it is not safe to assume
your version omits it.

## Object cache: Redis DB separation

The plugin's object-cache module talks to Redis independently of page
caching, and works fine on stock nginx. If you point it at the same Redis
instance cache-turbo's L2 uses:

```nginx
cache_turbo_redis redis://10.0.0.5:6379/0 prefix=wp: timeout=250ms
                  keepalive=32 keepalive_timeout=60s;
```

> **Give the page cache its own Redis DB (or instance) — same rule as
> [`wordpress.md`](wordpress.md#vhost-page-cache--redis-l2).** In the plugin's
> Cache > Object screen, set a **different `Database ID`** than the one
> `cache_turbo_redis` uses (`/0` vs `/1`), or point it at a separate instance
> entirely. Otherwise `cache_turbo_admin`'s `?all=1` purge and the plugin's
> object-cache flush can trample each other's keys, and worse, a shared prefix
> means cache-turbo's page-cache purge could wipe WordPress's internal
> object cache (transients, query cache) along with it.

## Purging on publish

Because LSCache's own page-cache is inactive on this stack, its purge-on-save
hooks have **nothing to purge** — they clear a cache that was never populated.
In v7.8.1 that machinery is `Purge::purge_post()`, hooked (via the
`litespeed_purge_post_events` filter, default `save_post` and friends) inside
`purge.cls.php`, plus the public `Purge::purge_all()` / `litespeed_purge_all`
action. All of it queues `X-LiteSpeed-Purge` tags that only a LiteSpeed engine
reads, so it is a no-op here. Don't wire anything to it. **cache-turbo's own
admin endpoint is what needs triggering** on publish, same as a plain
WordPress site:

```bash
curl -X POST 'http://127.0.0.1/_cache?key=/blog/my-post/'
curl -X POST 'http://127.0.0.1/_cache?all=1'   # after a theme/plugin-config change
```

Hook it from `save_post` / `transition_post_status` in your own mu-plugin,
pointed at `cache_turbo_admin`'s endpoint — not at the LiteSpeed Cache
plugin's `litespeed_purge_all` / `Purge::purge_all()` action, which is a no-op
on stock nginx and will not touch cache-turbo's zone.

## Checking it works

Same verification pattern as [`wordpress.md`](wordpress.md#checking-it-works),
plus a check that the plugin isn't fooling you into thinking it's serving the
cache:

```nginx
add_header X-Cache-Turbo $cache_turbo_status always;
```

```bash
# anonymous post: MISS then HIT — this is cache-turbo, not LSCache
curl -sI https://example.com/blog/hello/ | grep -i x-cache-turbo
curl -sI https://example.com/blog/hello/ | grep -i x-cache-turbo   # HIT

# confirm LSCache is NOT actually caching (expect no litespeed cache-hit signal)
curl -sI https://example.com/blog/hello/ | grep -i x-litespeed-cache
#  -> absent, or present-but-"miss" every time: confirms the engine isn't there

# logged-in: must always be BYPASS
curl -sI -H 'Cookie: wordpress_logged_in_abc=user|123|hash' \
     https://example.com/blog/hello/ | grep -i x-cache-turbo       # BYPASS
```

If you ever see a real `X-LiteSpeed-Cache: hit` header, the origin is not
stock nginx — stop and re-read the top of this doc, you may be on an actual
LiteSpeed/`ngx_lscache` box with two competing HTML caches.

## Gotchas

- **Don't chase "why is LSCache showing 0% hit rate."** It's supposed to be
  0% — the engine isn't there. That's cache-turbo's job on this stack, and
  its own stats (`GET /_cache`) are the ones that matter.
- **Don't disable the plugin outright** unless you don't want its optimizer
  features either — minify, image optimization, CDN mapping, and the Redis
  object-cache module all work fine on stock nginx and are unrelated to
  page-caching.
- **`X-LiteSpeed-Cache-Control` is not `Cache-Control`.** Don't assume setting
  the plugin's "public cache TTL" field changes what cache-turbo does with
  `cache_turbo_cache_control honor`. Stock nginx never sees that header; only
  `cache_turbo_valid` and the origin's real `Cache-Control` govern TTL here.
- **QUIC.cloud CDN is a separate product.** If the plugin's QUIC.cloud
  integration is enabled, that's an edge CDN cache in front of everything —
  a third cache layer, not covered by this doc. Treat it like any CDN in
  front of cache-turbo: purge it too, or disable it if cache-turbo already
  sits behind your CDN of choice.
- **Object-cache Redis DB collision is the one real conflict on this stack** —
  see the section above. Everything else is inert-by-absence, not a fight.
- **Revisit if the origin ever moves to real LiteSpeed/OpenLiteSpeed.** All
  "inert" claims in this doc flip the moment `ngx_lscache` or the LiteSpeed
  web server itself is in the stack — see the callout at the top.

## PHP settings / gotchas

These are **LiteSpeed-Cache-plugin-specific** load and correctness traps on
PHP-FPM — separate from the nginx-layer directives above. They bite because the
plugin's optimizer half runs full-speed on stock nginx even though its cache
half is dormant.

- **`_lscache_vary` cookie persistence with no engine.** As covered above, the
  plugin sets this ~2-day cookie (`_cookie()` in `vary.cls.php`, `expire =
  time() + 2 * DAY_IN_SECONDS`) on login/comment even though nothing on this
  stack will ever read it. It is harmless clutter for cache-turbo as long as
  you bypass on it, but be aware it exists so you don't mistake it for a
  cache-turbo cookie when debugging `Set-Cookie` headers. It rides the
  `is_ssl()` flag unless the plugin's "Improve HTTP/HTTPS Compatibility"
  (`O_UTIL_NO_HTTPS_VARY`) toggle is on.
- **Plugin Object Cache vs cache-turbo's L2 — two different jobs, one Redis.**
  The plugin's object cache (Cache > Object; `object-cache.cls.php`, keys
  `object-host`/`object-port`/`object-db_id`) is a WP **object**-cache drop-in
  (transients, query results, `wp_cache_*`). cache-turbo's Redis L2 is a
  **page/fragment** store. They serve different layers and should coexist, but
  **must not share a Redis DB index** — the plugin's `Database ID`
  (`O_OBJECT_DB_ID`) has to differ from `cache_turbo_redis`'s `/N`, or a flush
  on one side clears the other (see [Object cache: Redis DB
  separation](#object-cache-redis-db-separation)). Also don't run the plugin's
  object cache *and* another drop-in (Redis Object Cache, W3TC) — WordPress
  loads exactly one `object-cache.php`, last writer wins.
- **Crawler hammers PHP-FPM for zero benefit here.** The plugin's Crawler
  (Cache > Crawler; `crawler.cls.php`, off by default) walks your sitemap on a
  WP-cron interval, firing self-requests with user-agent `lscache_runner` to
  pre-warm LSCache. On stock nginx `Router::can_crawl()` still returns `true`,
  so if you switch it on it will happily generate FPM load warming a cache that
  does not exist. Leave it **disabled** — cache-turbo warms itself on first
  hit. If you must profile it, note it raises `max_execution_time` mid-run
  (`ini_set`), which can pin an FPM worker for the whole crawl window.
- **Image optimization / LQIP queue load.** Image Optimization (`img-optm.cls.php`)
  and low-quality placeholder generation are **pull-based against QUIC.cloud**,
  not local CPU, but each pull + WebP rewrite (`O_IMG_OPTM_WEBP`) runs through
  PHP on the cron/queue worker and rewrites markup on the fly in `media.cls.php`.
  On a busy publish schedule that queue can keep an FPM child busy; it is
  independent of caching and unaffected by cache-turbo, so budget FPM
  `pm.max_children` for it if you enable it. WebP mode 2 (replace `<img>`
  attrs) does the most per-request work.
- **opcache.** The plugin is large (hundreds of PHP classes autoloaded per
  request). Ensure `opcache.enable=1` with enough `opcache.memory_consumption`
  and a high `opcache.max_accelerated_files` (≥ 16k) so its class files stay
  compiled; otherwise every uncached (bypassed / logged-in) request pays the
  full parse cost. This matters more here than on a real LiteSpeed box because
  cache-turbo, not LSCache, is absorbing the anonymous hits — every request the
  plugin's optimizer touches is a PHP request.

## See also

- [`wordpress.md`](wordpress.md) — the base preset this doc layers on top of;
  cookie table, vhost pattern, purge-on-publish baseline.
- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend) — the
  preset table and how `cache_turbo_backend` composes.
- [README — Redis L2](../README.md#redis-l2-shared-cache) — full L2 DSN
  syntax, TLS, keepalive.
- [LSCache for WordPress — FAQ](https://docs.litespeedtech.com/lscache/lscwp/faq/) —
  upstream confirmation that caching requires a LiteSpeed server.
