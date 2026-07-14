# WordPress + cache-turbo

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
comment-author cookie, and any `?preview=` or `?s=` (search) request.

`wordpress` must be named explicitly — `cache_turbo_backend wordpress;` gets you
this plus the WooCommerce and Joomla rules.

## What the preset skips

| Check | Values |
|---|---|
| URI prefixes | `/wp-admin/`, `/wp-login.php`, `/wp-cron.php`, `/xmlrpc.php`, `/wp-json/` |
| Query args (presence) | `preview`, `s` |
| Cookie substrings | `wordpress_logged_in_`, `wp-postpass_`, `comment_author_` |

The cookie names are matched as **substrings**, because WordPress suffixes them
with a hash of the site (`wordpress_logged_in_a1b2c3…`) — an exact-name lookup
would never match.

`?s=` is skipped because search results are effectively unbounded in cardinality:
caching them lets any visitor fill your zone with junk keys and evict the pages
people actually read.

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

# admin + search + preview: BYPASS
curl -sI https://example.com/wp-admin/            | grep -i x-cache-turbo
curl -sI 'https://example.com/?s=test'            | grep -i x-cache-turbo
```

If a logged-in request ever returns `HIT`, stop — that's an authenticated page in
a shared cache.

## Gotchas

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
- **`?s=` search is skipped by design** (unbounded key cardinality). Don't add it
  back without a `cache_turbo_min_uses` guard.
- **WooCommerce?** Stack the presets: `cache_turbo_backend wordpress woocommerce;`
  — see [`woocommerce.md`](woocommerce.md).

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [README — The cache key](../README.md#the-cache-key)
- [`woocommerce.md`](woocommerce.md) — the WooCommerce add-on preset
- [`docs/README.md`](README.md) — all presets
