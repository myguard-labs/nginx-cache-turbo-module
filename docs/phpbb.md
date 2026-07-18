# phpBB + cache-turbo

_Last researched: 2026-07-18_

Caching a phpBB 3.x board. **The preset now protects logged-in members on its
own** — it carries a cookie **value** predicate. Earlier releases did not, and
required the hand-written `map` below; if you are upgrading, you can delete it.

- [The short version](#the-short-version)
- [Why a value predicate (and why the name is matched by suffix)](#why-a-value-predicate-and-why-the-name-is-matched-by-suffix)
- [Upgrading from the hand-written map](#upgrading-from-the-hand-written-map)
- [Vhost](#vhost)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)
- [PHP settings / gotchas](#php-settings--gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend phpbb;
```

That is the whole config. No `map`, no `cache_turbo_bypass`. The preset bypasses
the cache for any visitor whose `<cookie_name>_u` cookie holds anything other
than `1` — i.e. any logged-in member — and keeps caching for guests, who carry
`_u=1` (`ANONYMOUS`).

It works whatever your board's cookie prefix is: the cookie **name is matched by
suffix** (`_u`), so `phpbb_u`, `phpbb3_u`, and `myboard_xyz_u` all match. You do
not need to look your prefix up.

## Why a value predicate (and why the name is matched by suffix)

phpBB sets `_u` / `_k` / `_sid` for **every non-bot visitor, guests included** —
`session_create()` guards the `set_cookie()` block on `$bot`, not on login state.
So cookie *presence* tells you nothing: an anonymous visitor has all three. What
differs is the **value**:

| Visitor | `<prefix>_u` |
|---|---|
| Guest | `1` — the `ANONYMOUS` constant (`includes/constants.php`: `define('ANONYMOUS', 1)`) |
| Logged-in member | their `user_id` — **never** `1`, since `ANONYMOUS` is a reserved user row |

(`phpbb/session.php`, `session_create()`: `cookie_data['u'] = ($bot) ? $bot : ANONYMOUS;`
for the no-user path, `cookie_data['u'] = $this->data['user_id'];` for a real login.)

Hence `_u != 1`. A presence rule would match every guest — taking the hit rate to
zero while still failing to identify a member.

**The name is matched by suffix on purpose.** phpBB composes the cookie as
`config('cookie_name') . '_u'` (`set_cookie()`), and `cookie_name` is an ACP
setting — it defaults to `phpbb`, installers randomise it, and anyone running two
boards on one domain changes it. A rule keyed on a *literal* name silently stops
firing on such a board, and **a bypass rule that stops firing caches the member's
page and serves it to strangers.** Suffix matching is prefix-agnostic. It can
over-match an unrelated cookie ending in `_u` — a needless bypass, never a leak.

An unreadable `_u` (no `=`, malformed) **fails closed to bypass**: a false bypass
costs one cache miss; a false hit costs somebody else's session.

## Upgrading from the hand-written map

If you followed an earlier version of this guide, you have something like:

```nginx
map $http_cookie $phpbb_user {
    default                    "";
    "~phpbb3_u=(?!1(;|$))"     "1";
    "~phpbb3_k=[^;\s]+"        "1";
}
cache_turbo_bypass   $phpbb_user;
cache_turbo_no_store $phpbb_user;
```

**You can delete all of it.** The preset now does this itself, and does it
prefix-agnostically — which the `map` above did not: it hardcodes `phpbb3_`, so
it silently stopped protecting you if the ACP cookie name ever changed.

Keeping the `map` is harmless (the two rules agree), but it is dead weight and it
will drift. Note it also needs PCRE, which the module's own matcher does not.

## Vhost

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    server {
        listen 443 ssl http2;
        server_name forum.example.com;
        root /var/www/phpbb;
        index index.php;

        location / {
            try_files $uri $uri/ /index.php?$args;
        }

        location ~ \.php$ {
            cache_turbo               ct;
            cache_turbo_backend       phpbb;
            # The preset carries the _u != 1 value predicate: logged-in members
            # bypass automatically. No map, no cache_turbo_bypass needed.

            cache_turbo_valid         60s;
            cache_turbo_valid         404 410 1m;
            cache_turbo_preset        balanced;

            include                   fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_pass  unix:/run/php/php-fpm.sock;
        }

        # phpBB internals -- never HTTP-reachable, never cache candidates.
        # `^~` is load-bearing: regex locations are tested in DECLARATION order,
        # so a plain `~ ^/(cache|store|files)/` written after `~ \.php$` would
        # never run and /cache/data_global.php would execute in php-fpm.
        location ^~ /cache/ { deny all; }
        location ^~ /store/ { deny all; }
        location ^~ /files/ { deny all; }

        # Board styles / avatars / attachments: static, long-lived.
        location ~* ^/(styles|images|assets)/ {
            cache_turbo off;
            expires 30d;
            access_log off;
        }

        # Never cache attachment downloads -- they are permission-checked per user.
        # An `=` location outranks the `~ \.php$` regex, so this block must
        # repeat the FastCGI wiring itself. Without it nginx falls back to the
        # static handler and serves the raw PHP source.
        location = /download/file.php {
            cache_turbo off;

            include                   fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_pass  unix:/run/php/php-fpm.sock;
        }

        location = /_cache {
            cache_turbo_admin on;
            allow 127.0.0.1;
            deny  all;
        }
    }
}
```

## Checking it works

```nginx
add_header X-Cache-Turbo $cache_turbo_status always;
```

```bash
# anonymous topic: MISS then HIT
curl -s -o /dev/null -D- https://forum.example.com/viewtopic.php?t=1 | grep -i x-cache-turbo
curl -s -o /dev/null -D- https://forum.example.com/viewtopic.php?t=1 | grep -i x-cache-turbo  # HIT

# UCP / posting / admin: BYPASS (this is what the preset gives you)
curl -s -o /dev/null -D- https://forum.example.com/ucp.php | grep -i x-cache-turbo

# A GUEST carrying the full cookie set must still be a HIT. If this says BYPASS,
# your map is matching _sid or a bare _u= and you have destroyed your hit rate.
curl -s -o /dev/null -D- -H 'Cookie: phpbb3_sid=x; phpbb3_u=1; phpbb3_k=' \
     https://forum.example.com/viewtopic.php?t=1 | grep -i x-cache-turbo   # HIT

# THE ONE THAT MATTERS: a logged-in member must be BYPASS. If this says HIT/MISS,
# the preset is not active on this location -- you are one request away from
# serving a member's page, with their username and unread PM count, to the public.
curl -s -o /dev/null -D- -H 'Cookie: phpbb3_sid=x; phpbb3_u=42; phpbb3_k=beef' \
     https://forum.example.com/viewtopic.php?t=1 | grep -i x-cache-turbo   # BYPASS
```

Run **both** of those last two before you go live. The guest check protects your
hit rate; the member check protects your users. Use your board's real prefix if
you like — but the member check should pass with *any* prefix, because the name is
matched by suffix. That is worth confirming on your own board.

> These probes use `GET` (`-s -o /dev/null -D-`), not `curl -sI`. A `HEAD` request
> is **never stored** by the module, so `curl -sI` can never show you a `HIT` — it
> will make a working cache look broken.

## Gotchas

- **`_sid` is not an auth cookie.** Neither is a bare `_u=`. Guests have both.
  Bypassing on either is the classic mistake and it costs you the entire cache.
  (This is why the preset tests the `_u` **value** and ignores `_sid` entirely.)
- **Renaming the cookie in the ACP is safe** for the preset — the name is matched
  by suffix (`_u`), so any prefix works. It is **not** safe for a hand-written
  `map` that hardcodes `phpbb3_`; if you still have one, delete it.
  after any ACP cookie change.
- **`?sid=` in URLs.** phpBB's `append_sid()` adds the session id as a `sid=` GET
  arg whenever a cookie is not yet known to work — the first request of a session,
  or a genuinely cookieless client — and forces it into ACP/MCP links for CSRF
  hardening. It is not a simple ACP on/off toggle; treat it as always possible.
  The preset bypasses on the `sid` arg — it is both a dynamic marker and a
  cache-key poisoning vector. Leave that rule on.
- **`/download/file.php` is permission-checked.** Attachments in a private forum
  must never be cached; the vhost above turns cache-turbo off for it entirely.
- **phpBB does not send `Cache-Control: private` reliably.** Unlike Drupal and
  MediaWiki, you get no second line of defence from the origin here.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached, regardless of preset. Those floors hold — but note a logged-in
  member browsing normally sends only cookies and gets no `Set-Cookie`, so the
  floor does **not** save you.

## PHP settings / gotchas

These are the phpBB-specific PHP/PHP-FPM points that interact with the cache; the
generic FastCGI tuning (buffers, `request_terminate_timeout`) is the same as any
PHP app and is out of scope here.

- **phpBB uses cookie + DB sessions, not PHP native sessions.** Login state lives
  in the `phpbb_sessions` table keyed by the `_sid` cookie; phpBB does not touch
  PHP's native `$_SESSION` / `session.save_handler`. So none of the `session.*`
  php.ini knobs (save path, GC, cookie params) affect who is "logged in" as far as
  the cache is concerned. The edge also receives `_sid`, `_k`, and the `sid`
  query argument, but phpBB's own `_u` cookie is the preset's auth signal — its
  bypass predicate tests `_u` alone (classifying the request as bypass; it does
  not fold the cookie into the cache key). Do not reach for `session.cookie_*`
  tuning to fix a cache-vs-login problem; it cannot help.
- **`_u == 1 == guest` is the load-bearing invariant — bank it.** The preset's
  entire correctness rests on `ANONYMOUS` being `1` (`includes/constants.php`:
  `define('ANONYMOUS', 1)`), still true in 3.3.x and on 4.0 `master`. Two ways it
  could theoretically break: phpBB renumbering `ANONYMOUS` (it has not in the 3.x
  line), or an extension that issues its own login cookie without writing a real
  `user_id` into `_u`. Neither is a live concern today, but if you run an auth
  extension, confirm the logged-in member check below still returns `BYPASS`.
- **OPcache: enable it, and don't confuse it with the page cache.** phpBB runs
  cleanly under OPcache and expects it in production. Note that the ACP *Purge
  cache* action also flushes OPcache — so there are now *three* independent caches
  in play (OPcache = compiled PHP bytecode, phpBB's `cache/` = compiled Twig
  templates + config, cache-turbo = rendered HTML). Purging one does nothing to
  the others.
- **phpBB's own `cache/` is not the module's cache.** An ACP purge (or a system
  cron `tidy_cache`) clears `cache/`, but it does **not** touch cache-turbo — the
  already-rendered HTML keeps being served until its `cache_turbo_valid` TTL
  lapses. After a board-wide content or style change, either accept the TTL lag
  (the vhost above uses `cache_turbo_valid 60s`, which bounds it) or purge the
  edge explicitly through the `_cache` admin endpoint. The nginx sample config
  ships with `cache/`, `store/` and `files/` denied to direct HTTP access; leave
  those denials in place — they are phpBB internals, never cache candidates.
- **`memory_limit`.** phpBB's floor is 128M; large boards and, especially,
  attachment handling want more (256M is a safe medium-board value). Thumbnail
  generation in `download/file.php` loads full images into memory via GD — and
  because that endpoint is permission-checked it is uncached (`cache_turbo off`
  above), so *every* attachment view is a live PHP request. A too-low
  `memory_limit` surfaces as broken image downloads, not as a cache fault.
- **`max_execution_time` for `cron.php` and the ACP purge.** phpBB's board cron
  (`cron.php`, doing `tidy_cache` / `tidy_sessions` / `tidy_database`) and the ACP
  *Purge cache* action can run long on a big board; a tight `max_execution_time`
  (or FPM `request_terminate_timeout`) truncates them mid-run and can leave a
  half-cleared cache. These are all POST/admin/cron paths the preset already
  bypasses, so cache-turbo never *masks* a failed purge — but a truncated cron is
  why "I purged and nothing changed" sometimes has nothing to do with the edge.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/joomla.md`](joomla.md) — the other preset with no cookie rule
- [`docs/README.md`](README.md) — all presets
