# XenForo + cache-turbo

Full-page caching a XenForo (XF2) board: what to cache, what to bypass, what to
put in the key, and a copy-paste vhost with the Redis L2 tier wired up.

- [The short version](#the-short-version)
- [Why not just key on the session cookie?](#why-not-just-key-on-the-session-cookie)
- [Cookies: bypass vs key](#cookies-bypass-vs-key)
- [Vhost: page cache only](#vhost-page-cache-only)
- [Vhost: page cache + Redis L2 (shared across a fleet)](#vhost-page-cache--redis-l2-shared-across-a-fleet)
- [Board in a subdirectory](#board-in-a-subdirectory)
- [XenForo's own object cache (Redis) — a different thing](#xenforos-own-object-cache-redis--a-different-thing)
- [Purging on new posts](#purging-on-new-posts)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend xenforo;
cache_turbo_key     $host$uri$cookie_xf_style_variation$cache_turbo_normalized_args;
```

`cache_turbo_backend xenforo` auto-skips the dynamic surfaces — the auth flows,
the admin CP, the installer, `/account`, DMs, `/misc` — and bypasses any request
carrying `xf_user` (a logged-in member) or `xf_session_admin`. Guests get cached
pages; members always hit the origin and their HTML is **never stored**.

`xenforo` is **not** part of `generic`/`auto`, unlike the WordPress, WooCommerce
and Joomla presets. Its URI prefixes are generic English words (`/login`,
`/register`, `/contact`, `/misc`) that a non-forum site can legitimately serve as
cacheable pages, so folding it into the union would punch holes in unrelated
sites' caches. Name it explicitly.

## Why not just key on the session cookie?

The tempting one-liner is to add the session cookie to the cache key, so that
"the login page areas are still cached":

```nginx
# WRONG.
cache_turbo_key $host$uri$cookie_xf_session$cache_turbo_normalized_args;
```

This does not do what it looks like it does. Two separate problems:

1. **It doesn't share anything.** A per-session component in the key mints a
   *distinct cache entry per visitor*. Nobody ever hits anybody else's entry, so
   the hit rate on those pages collapses to roughly zero — you've replaced a
   cache with a very elaborate memory leak, and the LRU churn evicts the
   genuinely shared pages that were working fine.

2. **It still stores authenticated HTML.** Bypass means *never captured*. A
   per-session key means captured, just filed under a longer name. The moment the
   origin forgets a `private` on some page, or an add-on renders a member's DM
   preview into a "shared" template, that response is sitting in the cache. The
   key doesn't protect you; not storing it does.

The rule: **key on the *variant*, bypass the *identity*.** A variant (theme,
language) changes how a page is rendered but the page is still shared by
everyone who picked that variant. An identity (who you are logged in as) is not
shared with anyone, ever.

## Cookies: bypass vs key

| Cookie | Treatment | Why |
|---|---|---|
| `xf_user` | **bypass** | persistent login cookie — an authenticated member |
| `xf_session_admin` | **bypass** | admin-CP session |
| `xf_session` | **ignore** | XF issues this to **guests too**. Bypassing on it drops every visitor who touched a form out of the cache — that's most of your traffic. Not an auth marker. |
| `xf_style_variation` | **cache key** | light/dark variant. Shared, not private. Bypassing on it means a visitor who picked dark theme never gets a cached page again. |
| `xf_language_id` | **cache key** (multi-language boards) | same reasoning |

This is the same split [LiteSpeed's XenForo cache
plugin](https://docs.litespeedtech.com/lscache/lscxf/installation/) makes: it
bypasses on `xf_user` / `xf_session_admin`, and *varies* on style + language.

Only add the cookies you actually vary on to the key. A single-style,
single-language board should keep the plain default key — every component you add
splits the cache.

## Vhost: page cache only

Board at the domain root, PHP-FPM behind it.

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    server {
        listen 443 ssl http2;
        server_name forum.example.com;
        root /var/www/xenforo;
        index index.php;

        # XF's front controller: everything that isn't a real file is a route.
        location / {
            try_files $uri $uri/ /index.php?$uri&$args;
        }

        # Never let the internals be served or cached.
        location ~ ^/(internal_data|library|src)/ { internal; }

        location ~ \.php$ {
            cache_turbo               ct;
            cache_turbo_backend       xenforo;

            # Theme is a shared variant -> key. Identity -> bypassed by the preset.
            cache_turbo_key           $host$uri$cookie_xf_style_variation$cache_turbo_normalized_args;

            cache_turbo_valid         60s;        # guests see a page at most 60s old
            cache_turbo_valid         404 410 1m; # negative caching
            cache_turbo_preset        balanced;   # SWR window: stale served while one refresh runs

            # XF sends `Cache-Control: private` on a lot of guest-visible pages.
            # The preset already defaults this to `honor`; pin it to `respect` so
            # cache_turbo_valid drives the TTL and CC only gates storage.
            cache_turbo_cache_control respect;

            # Belt and braces on top of the preset: never store a response that
            # sets a cookie, and never store for a request with a member cookie.
            cache_turbo_no_store      $cookie_xf_user;

            include                   fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_pass  unix:/run/php/php-fpm.sock;
        }

        # Static assets: let nginx serve them, no point caching in shm.
        location ~* \.(css|js|png|jpe?g|gif|webp|svg|woff2?)$ {
            cache_turbo off;
            expires 30d;
            access_log off;
        }

        # Admin endpoint — purge + stats. NEVER public.
        location = /_cache {
            cache_turbo_admin on;
            allow 127.0.0.1;
            allow 10.0.0.0/8;
            deny  all;
        }
    }
}
```

## Vhost: page cache + Redis L2 (shared across a fleet)

Same as above, plus a shared L2 so several front-ends share one cache and a cold
box isn't cold. L1 (shm, per box) is checked first; only an L1 miss touches
Redis. Add to the `http` block:

```nginx
http {
    cache_turbo_zone  name=ct 256m;

    # Shared L2. Inherited by every server/location below.
    cache_turbo_redis redis://10.0.0.5:6379/0 prefix=xf: timeout=250ms
                      keepalive=32 keepalive_timeout=60s;

    # TLS to a managed Redis instead:
  # cache_turbo_redis rediss://redis.internal:6380/0;
    ...
}
```

Nothing in the `location` block changes — the L2 is transparent. Use a distinct
`prefix=` per site if the Redis instance is shared, so two boards don't collide.

> **Give the page cache its own Redis DB (or instance).** Do not point
> `cache_turbo_redis` at the same DB XenForo uses for its own object cache (see
> below) — a `?all=1` purge here would blow away XF's internal cache too. Use a
> different DB number (`/0` vs `/1`), or a different `prefix=`, or both.

## Board in a subdirectory

If the board lives at `/forums/` rather than the root, every URI prefix in the
preset shifts. The preset matches on `r->uri` from the site root, so scope it to
the board's location and the prefixes line up on their own:

```nginx
location /forums/ {
    try_files $uri $uri/ /forums/index.php?$uri&$args;
}

location ~ ^/forums/.*\.php$ {
    cache_turbo         ct;
    cache_turbo_backend xenforo;   # matches /forums/login, /forums/admin.php, ...
    ...
}
```

Careful: the preset's prefixes are matched against the **full** URI. A board at
`/forums/` serves `/forums/login`, which does *not* start with `/login` — so the
preset's `/login` prefix will not match it. Scoping the `location` is not enough
on its own; add explicit bypasses for the auth surfaces:

```nginx
location ~ ^/forums/ {
    cache_turbo         ct;
    cache_turbo_backend xenforo;                # still catches the xf_user cookie
    cache_turbo_bypass  $subdir_dynamic;        # ...and the shifted URIs
}
```

with, in `http`:

```nginx
map $uri $subdir_dynamic {
    default                                  "";
    "~^/forums/(admin\.php|install/|login|logout|lost-password|register|account|conversations|direct-messages|contact|misc)"  "1";
}
```

The cookie half of the preset (`xf_user`, `xf_session_admin`) is path-independent
and keeps working regardless — so even if you skip the map, a logged-in member is
never served or stored from cache. The map only covers the *anonymous* hits on
those URIs.

## XenForo's own object cache (Redis) — a different thing

Worth separating, because "caching" means two things here and they don't overlap:

| Layer | What it holds | Configured where |
|---|---|---|
| **cache-turbo** (this module) | rendered **HTML pages**, in nginx, for guests | this vhost |
| **XenForo object cache** | XF's internal data (templates, phrases, permissions), in Redis/APCu, for *every* request incl. members | XF's `src/config.php` |

They are complementary: the object cache makes the *origin* fast (which is what
members and cache-turbo misses hit), and cache-turbo means guests don't reach the
origin at all. Turn both on.

XF's object cache is configured in `src/config.php`, not in nginx — e.g. with
Redis via the `Cm_Cache_Backend_Redis` provider:

```php
$config['cache']['enabled'] = true;
$config['cache']['provider'] = 'Redis';
$config['cache']['config'] = [
    'server'   => '10.0.0.5',
    'port'     => 6379,
    'database' => 1,          // NOT the db cache-turbo's L2 uses
];
```

Check XenForo's [cache support docs](https://xenforo.com/docs/xf2/cache/) for
the current provider list — this is XF's business, not the module's. The only
thing that matters on our side is the **database/prefix separation** noted above.

## Purging on new posts

A 60s TTL means a new post shows up to guests within a minute, which is usually
fine for a forum. If you want it immediate, purge the thread's key when a post
lands — the admin endpoint takes a key or a tag:

```bash
curl -X POST 'http://127.0.0.1/_cache?key=/threads/some-thread.1234/'
curl -X POST 'http://127.0.0.1/_cache?all=1'    # nuke the zone (e.g. after a style change)
```

Wire it from an XF add-on listening on `post_save` if you need it automatic.
Purging after a **style/template change** is the other common one — a rebuilt
style changes every rendered page.

## Checking it works

`$cache_turbo_status` tells you what happened. Expose it while you're tuning:

```nginx
add_header X-Cache-Turbo $cache_turbo_status always;
```

The three that matter for XenForo:

```bash
# guest thread page: MISS then HIT
curl -sI https://forum.example.com/threads/hello.1/ | grep -i x-cache-turbo
curl -sI https://forum.example.com/threads/hello.1/ | grep -i x-cache-turbo   # HIT

# logged-in member: must always be BYPASS
curl -sI -H 'Cookie: xf_user=1234%2Cabcdef' \
     https://forum.example.com/threads/hello.1/ | grep -i x-cache-turbo       # BYPASS

# auth surface: must always be BYPASS
curl -sI https://forum.example.com/login | grep -i x-cache-turbo              # BYPASS
```

If a member request ever returns `HIT`, stop and fix it before going live —
that's a logged-in page being served from a shared cache. (It shouldn't: the
preset bypasses `xf_user`, and the `Set-Cookie` safety floor blocks storage
independently.)

`GET /_cache` gives you the counters; `bypasses` should track your logged-in
traffic, and the hit ratio should be dominated by guest thread/forum views.

## Gotchas

- **Custom cookie prefix.** The preset assumes XenForo's default
  `$config['cookie']['prefix'] = 'xf_'`. If you changed it, `xf_user` never
  matches and **logged-in pages become cacheable** — the one failure mode that
  actually leaks. Add `cache_turbo_bypass $cookie_<yourprefix>user;` to be safe,
  or leave the prefix at its default.
- **`/misc` is load-bearing.** It's XF's style/language picker and inline
  dispatch endpoint (`/misc/style`, `/misc/language`) — a `POST` that sets a
  cookie. Cached, it breaks the theme switcher. The preset bypasses it.
- **Add-ons add surfaces.** The preset covers stock XF2 routes. An add-on that
  ships its own member-only route (`/my-shop/orders`) needs its own
  `cache_turbo_bypass` — the preset is a floor, not a security boundary.
- **`Set-Cookie` responses are never stored** regardless of preset, and a request
  with an `Authorization` header is never cached. Those floors are unconditional.
- **Two boards, one Redis.** Use distinct `prefix=` values, or `?all=1` on one
  purges the other.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend) — the
  preset table and how `cache_turbo_backend` composes.
- [README — The cache key](../README.md#the-cache-key) — normalization, what
  `$cache_turbo_normalized_args` strips.
- [README — Redis L2](../README.md#redis-l2-shared-cache) — the full L2 DSN
  syntax, TLS, keepalive.
