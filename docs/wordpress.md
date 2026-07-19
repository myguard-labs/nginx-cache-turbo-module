# WordPress + cache-turbo

_Last researched: 2026-07-18_

Full-page caching a WordPress site: what the preset skips, what to key on, and a
copy-paste vhost with the Redis L2 tier.

- [The short version](#the-short-version)
- [What the preset skips](#what-the-preset-skips)
- [Cookies: bypass vs key](#cookies-bypass-vs-key)
- [Vhost: page cache only](#vhost-page-cache-only)
- [Vhost: page cache + Redis L2](#vhost-page-cache--redis-l2)
- [WordPress's own object cache — a different thing](#wordpresss-own-object-cache--a-different-thing)
- [Purging on publish](#purging-on-publish)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend wordpress;
```

That's it — the default key is right for a stock WordPress site. The preset
auto-skips `/wp-admin/`, `/wp-login.php`, `/wp-cron.php`, `/xmlrpc.php` and
`/wp-json/`, plus any request carrying a logged-in / password-protected-post /
comment-author cookie, and any `?preview=` request. Site search (`?s=`) is
**cached**, not bypassed — see below.

Each preset is its own independent bit — `cache_turbo_backend wordpress;`
activates the WordPress rules and **nothing else**. It does not imply
WooCommerce and it does not imply Joomla. If the site runs WooCommerce you must
stack the presets explicitly:

```nginx
cache_turbo_backend wordpress woocommerce;
```

Relying on `wordpress` alone on a shop leaves `/cart`, `/checkout`,
`/my-account` and `?wc-ajax=` cacheable along with all three Woo cart cookies —
i.e. one customer's basket served to the next visitor. See
[woocommerce.md](woocommerce.md).

## What the preset skips

| Check | Values |
|---|---|
| URI prefixes | `/wp-admin/`, `/wp-login.php`, `/wp-cron.php`, `/xmlrpc.php`, `/wp-json/` |
| Query args (presence) | `preview`, `rest_route` |
| Cookie header substrings | `wordpress_logged_in_`, `wp-postpass_`, `comment_author_` |

> **Subdirectory installs.** The URI prefixes above are root-relative literals
> matched from byte 0 of `r->uri`, so an install mounted under a subdirectory
> (`/shop/`, `/forum/`, …) matches **none** of them — the admin surface
> included. Declare the mount with `cache_turbo_backend_prefix /shop/;` and the
> preset URI tier is compared against the rebased path. Scoping the nginx
> `location` does **not** substitute: it routes requests, it does not rewrite
> `r->uri`. See [frameworks.md](frameworks.md).

These literals are matched as **substrings of the whole `Cookie` header** —
names *and* values, searched undelimited — because WordPress suffixes the names
with a hash of the site (`wordpress_logged_in_a1b2c3…`) and an exact-name lookup
would never match. Note the match is not anchored to a cookie name, so a cookie
*value* containing one of these literals bypasses too; all three are distinctive
enough that this does not happen by accident.

`?s=` (site search) is **cached**. It used to be bypassed, on the grounds that
search results are unbounded in cardinality and let any visitor fill the zone
with junk keys. The cardinality problem is real; bypassing was the wrong answer
to it.

- A logged-out visitor's results are **anonymous-identical** — everyone
  searching "foo" gets the same page. That is shared, hot content.
- A logged-in editor's results *do* include drafts and private posts, but that
  visitor is already bypassed by `wordpress_logged_in_*` on the cookie tier. The
  arg rule added no safety.
- Bypassing made load *worse*. A bypass returns before the single-flight lock,
  so bypassed requests get no miss-collapsing: a `?s=` flood put 100% of its
  load on the origin, uncollapsed, on the most expensive query WordPress runs (a
  full-text `LIKE` scan of `wp_posts`).

Use **`cache_turbo_min_uses N`** for the cardinality half. It stores an entry
only after N misses, so once-seen junk terms never mint one while terms real
visitors repeat still cache — bounded keyspace, no origin flood.

## Cookies: bypass vs key

| Cookie | Treatment | Why |
|---|---|---|
| `wordpress_logged_in_*` | **bypass** | an authenticated user (any role) |
| `wp-postpass_*` | **bypass** | reader of a password-protected post — the HTML is not public |
| `comment_author_*` | **bypass** | WP renders "logged in as…" + the moderation state into the page |
| `wordpress_test_cookie` | **ignore** | set on every visit to the login page; means nothing |
| `wp-settings-*` | **ignore** | admin-screen UI prefs; irrelevant to public pages |

Note `comment_author_*`: it's tempting to treat a commenter as anonymous, but WP
personalises the comment form (and shows their unapproved comments) for them, so
their copy of a post is genuinely different. Bypass it.

There's nothing here that belongs in the *key* on a stock site — WordPress serves
one shared rendering to all anonymous visitors. If you run a multilingual plugin
that varies on a cookie, add that one cookie to `cache_turbo_key`.

## Vhost: page cache only

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

            # The preset defaults cache_control to `honor`, which means a plugin's
            # own Cache-Control drives the TTL. Pin it to `respect` if you'd rather
            # cache_turbo_valid decide and CC only gate storage.
          # cache_turbo_cache_control respect;

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

## Vhost: page cache + Redis L2

Add a shared L2 so a fleet of front-ends share one cache. L1 (per-box shm) is
checked first; only an L1 miss touches Redis. In `http`:

```nginx
cache_turbo_redis redis://10.0.0.5:6379/0 prefix=wp: timeout=250ms
                  keepalive=32 keepalive_timeout=60s;
```

The `location` block is unchanged — the L2 is transparent.

> **Separate it from WP's own Redis.** If you also run a WP object-cache plugin
> against Redis, give cache-turbo a **different database number or `prefix=`** —
> otherwise a `?all=1` purge here nukes WordPress's internal object cache too.

## WordPress's own object cache — a different thing

Two layers, easy to conflate:

| Layer | Holds | Configured where |
|---|---|---|
| **cache-turbo** | rendered **HTML pages**, in nginx, for anonymous visitors | this vhost |
| **WP object cache** (Redis/Memcached drop-in) | WP's internal query/option data, for **every** request incl. logged-in | `wp-content/object-cache.php` |

Complementary. The object cache makes the *origin* fast — which is what
logged-in users and cache-turbo misses hit. cache-turbo means anonymous visitors
don't reach PHP at all. Run both.

## Purging on publish

A 60s TTL means a new post is live within a minute. For instant, purge on publish:

```bash
curl -X POST 'http://127.0.0.1/_cache?key=/blog/my-post/'
curl -X POST 'http://127.0.0.1/_cache?all=1'          # after a theme change
```

Hook it from `save_post` / `transition_post_status` in a mu-plugin. Remember a
new post also changes the **front page**, the category archive, and the feed —
purge those keys too, or accept the TTL on them.

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

# admin + preview: BYPASS
curl -sI https://example.com/wp-admin/            | grep -i x-cache-turbo
curl -sI 'https://example.com/?preview=true'      | grep -i x-cache-turbo

# search is CACHED, not bypassed -- a second identical search should HIT
curl -sI 'https://example.com/?s=test'            | grep -i x-cache-turbo
curl -sI 'https://example.com/?s=test'            | grep -i x-cache-turbo
```

If a logged-in request ever returns `HIT`, stop — that's an authenticated page in
a shared cache.

## Gotchas

- **`?rest_route=` is bypassed too, and it is not a corner case.** `/wp-json/`
  is a *rewrite* to `index.php?rest_route=/...` — `wp-includes/rest-api.php`
  registers the rule, and `rest_api_loaded()` dispatches only when that query
  var is set. With plain permalinks the request never carries a `/wp-json/`
  path at all, so guarding only the path left `GET /?rest_route=/wp/v2/users/me`
  cacheable. Same API, two addressings, both now covered.
- **`/wp-json/` is bypassed wholesale.** That includes *public, cacheable* REST
  endpoints. If you serve a public API from `/wp-json/` and want it cached, give
  it its own `location` with `cache_turbo_backend` unset (and think hard about
  auth first).
- **Admin-bar users.** A logged-in user gets the admin bar injected into the
  front end, which is exactly why `wordpress_logged_in_*` must bypass. Never
  "optimise" that away.
- **Plugins that set cookies on the fly** (A/B tests, consent banners, carts)
  produce `Set-Cookie` responses, which are **never stored** regardless of preset.
  That's a floor, not a bug — but it can silently tank your hit rate. Check the
  `bypasses` counter if the ratio looks wrong.
- **`?s=` search is CACHED by design.** It is anonymous-identical, and a
  logged-in editor is covered by the cookie tier. If unbounded search-key
  cardinality worries you, that is what `cache_turbo_min_uses N` is for — do not
  reach for a bypass, which removes miss-collapsing and floods the origin.
- **WooCommerce?** Stack the presets: `cache_turbo_backend wordpress woocommerce;`
  — see [`woocommerce.md`](woocommerce.md).

## Forum / community plugins: bbPress, wpForo, Asgaros, BuddyPress, BuddyBoss

These are all pure WordPress plugins — forum posts/topics/replies, activity
feeds, private messages, all live as WP custom post types / DB tables, and
none of them define their **own** session/auth cookie. Identity is decided
entirely by WP core's `wordpress_logged_in_*` cookie, which the `wordpress`
preset above already bypasses on. **There is no `bbpress` / `wpforo` /
`asgaros` / `buddypress` / `buddyboss` preset, and there will not be one** —
adding a redundant preset bit would either duplicate the existing bypass for
no gain, or (if built around one of these plugins' own cosmetic cookies by
mistake) silently bypass guests too for zero added safety, which is exactly
the false-sense-of-safety trap this module's docs keep warning about.

Each plugin's own cookies were checked and are cosmetic/UI-state, guest-issued,
never an identity signal — fold them into the cache key if you care about
their variants, never into a bypass rule:

| Plugin | Its own cookies (all guest-issued, cosmetic) |
|---|---|
| bbPress | none of its own — rides `wordpress_logged_in_*` entirely |
| wpForo | a read-tracking "visited forums/topics" cookie; guest-post name/email cookies (only when guest posting is enabled) |
| Asgaros Forum | none confirmed beyond WP core |
| BuddyPress | `bp-activity-oldestpage`, `bp-activity-filter`, `bp-activity-scope`, `bp-messages-last-check` |
| BuddyBoss | `bp-activity-scope`, `bp-activity-filter`, `bp-activity-oldestpage`, `bp-better-messages-open-threads` |

What these plugins **do** add is front-end URI surface the stock `wordpress`
preset's admin/login-only URI list doesn't know about — regular front-end
pages that are per-user dynamic content, not `/wp-admin/`. Bypass these
explicitly:

```nginx
cache_turbo         ct;
cache_turbo_backend wordpress;

# Forum/community plugin surfaces the stock preset doesn't cover:
cache_turbo_bypass_uri
    /members/          # BuddyPress/BuddyBoss profiles
    /groups/           # BuddyPress/BuddyBoss groups — see note below
    /activity/         # BuddyPress/BuddyBoss activity feed
    /notifications/    # BuddyPress/BuddyBoss
    /messages/;         # BuddyPress/BuddyBoss private messages

# All plugin AJAX rides admin-ajax.php, which the wordpress preset's
# /wp-admin/ prefix already bypasses wholesale — no extra rule needed for
# bbp-*, wpforo_*, bp-*/activity_*/messages_*/groups_* action names.
```

**Private BuddyPress/BuddyBoss groups are a special case worth calling out
explicitly:** membership in a specific private group lives in the WP database
(`bp_groups_members` table), not in any cookie. There is no cookie signal for
"is this viewer a member of THIS group" — bypassing by cookie cannot express
it. If you run private groups, either exclude `/groups/` from caching entirely
(`cache_turbo off` in a nested `location`) or accept that a private group's
activity feed must never be cached keyed on cookies alone.

`/forums/` topic and reply **submission** is a normal WP `POST` to the
topic/forum permalink (not a separate URI) — already excluded by the general
"POST bypasses" behavior most cache-turbo installs rely on; the corresponding
`GET` on the same URL is the common, safely-cacheable-for-guests case and
needs no special handling.

## PHP settings / gotchas

cache-turbo keeps anonymous visitors away from PHP entirely, but every
*bypass* — logged-in users, the cart, admin-ajax, a cache miss — still lands in
PHP-FPM. A few WordPress-specific PHP settings decide whether those requests
stay fast, and one of them can quietly wreck your hit rate.

- **`session_start()` in a plugin is the classic hit-rate killer.** WordPress
  core deliberately does **not** use PHP sessions — it keeps state in cookies and
  the database. But some plugins (older forum, quiz, membership and "smart
  coupon" plugins are repeat offenders) call `session_start()` on every request,
  which makes PHP emit a `Set-Cookie: PHPSESSID=…` on the response. Per the
  "plugins that set cookies on the fly" rule above, a response carrying
  `Set-Cookie` is **never stored**, so a plugin that starts a session on every
  front-end page turns your hit rate to zero without a single error in the log.
  Worse, if you ever add `$cookie_PHPSESSID` to `cache_turbo_key` to "make it
  work", you fragment the cache one entry per visitor — cache-busting, not
  caching. The fix is upstream, not in nginx: find the `session_start()` call
  (`grep -rn session_start wp-content/`) and remove it or replace the plugin; a
  well-behaved WordPress plugin never needs one.

- **`DONOTCACHEPAGE` is invisible to nginx.** The `DONOTCACHEPAGE` constant is
  the de-facto standard PHP-side plugins use to opt a page out of caching, but
  it is a runtime PHP constant — cache-turbo, sitting in front of PHP-FPM, never
  sees it. It only reaches nginx if the plugin translates it into a real
  response header (e.g. a `Cache-Control: no-cache`/`no-store`). Because the
  `wordpress` preset defaults `cache_control` to `honor`, such a header will
  already suppress storage; if you pin `cache_turbo_cache_control respect;` you
  give that decision back to `cache_turbo_valid` and a `DONOTCACHEPAGE`-driven
  header only gates storage rather than the TTL. Either way, do not expect the
  bare constant to do anything at the nginx tier — verify the plugin actually
  emits a header.

- **opcache sizing scales with plugin count, not site size.** A stock WordPress
  install is a few hundred PHP files; add WooCommerce, a page builder and a
  couple of big plugins and you cross the `opcache.max_accelerated_files`
  default of ~10 000 easily. Once opcache is full it evicts hot files and
  re-compiles them on demand, so every bypass (the requests that *don't* hit
  cache-turbo) pays a compile tax. Size it to the actual file count
  (`find /var/www/wordpress -name '*.php' | wc -l`, round up to the next prime
  opcache accepts) and give `opcache.memory_consumption` headroom (256 MB is
  reasonable for a heavy plugin set). On a read-mostly production box,
  `opcache.validate_timestamps=0` is the biggest single win — but remember to
  reload PHP-FPM on every deploy, or new code silently won't take effect.

- **WordPress layers its own memory limits on top of PHP's.** `memory_limit` in
  the PHP-FPM pool is the hard ceiling, but WordPress applies its own softer
  limits underneath it: `WP_MEMORY_LIMIT` (front end, default 40 MB — 64 MB on
  multisite) and `WP_MAX_MEMORY_LIMIT` (admin only, default 256 MB). Heavy
  themes and builders routinely exhaust the 40 MB front-end figure and fatal
  *before* they reach the PHP ceiling, which looks like a random white screen on
  a cache miss while the admin (running under the 256 MB limit) is fine. Raise
  `WP_MEMORY_LIMIT` in `wp-config.php` and make sure the pool's `memory_limit`
  sits above it — the lower of the two always wins.

- **`max_execution_time` bites on the surfaces cache-turbo bypasses, not the
  cached ones.** Cached pages are served without touching PHP, so their timeout
  is irrelevant. The requests that *do* run PHP — `admin-ajax.php`, the REST API,
  imports/exports, Action Scheduler and `wp-cron.php` — are exactly the
  long-running ones, and they are all bypassed by the preset. Set a
  `max_execution_time` (and matching `fastcgi_read_timeout`) that suits those
  admin workloads; it will never slow a cache hit because a hit never reaches
  the interpreter.

- **The object-cache drop-in is a PHP-FPM concern, not an nginx one.** The
  Redis/Memcached drop-in described under "WordPress's own object cache" lives at
  `wp-content/object-cache.php` and depends on the matching PHP extension
  (`php-redis` or `php-memcached`) being loaded in the **PHP-FPM** pool that
  cache-turbo forwards to. If that extension is missing, WordPress silently falls
  back to a non-persistent, per-request cache — no error, just a slow origin on
  every cache-turbo miss and every logged-in request. Confirm the extension is
  loaded (`php-fpm -m | grep -i redis`) rather than trusting that the drop-in
  file exists.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [README — The cache key](../README.md#the-cache-key)
- [`woocommerce.md`](woocommerce.md) — the WooCommerce add-on preset
- [`docs/README.md`](README.md) — all presets
