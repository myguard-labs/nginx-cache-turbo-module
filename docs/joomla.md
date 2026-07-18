# Joomla + cache-turbo

_Last researched: 2026-07-18_

Caching a Joomla site. **Read [the warning](#the-preset-is-thin--read-this)
first** — the Joomla preset is deliberately minimal and, unlike the other three,
it does **not** protect logged-in users on its own.

- [The short version](#the-short-version)
- [The preset is thin — read this](#the-preset-is-thin--read-this)
- [Finding your session cookie](#finding-your-session-cookie)
- [Vhost](#vhost)
- [Vhost + Redis L2](#vhost--redis-l2)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend joomla;
cache_turbo_bypass  $cookie_<your_joomla_session_cookie>;   # ← REQUIRED, see below
```

The preset alone skips `/administrator/` and nothing else. The
`cache_turbo_bypass` line is not optional garnish — without it, a logged-in
Joomla user's page can be stored and served to the public.

## The preset is thin — read this

| Check | Values |
|---|---|
| URI prefixes | `/administrator/` |
| Query args | — |
| Cookie substrings | `joomla_remember_me_` |

## The cookie rule is a PARTIAL guard. Read this before you rely on it.

`joomla_remember_me_` is the one Joomla cookie that is both **matchable** and
**auth-only**. It is built as `'joomla_remember_me_' . getShortHashedUserAgent()`
— the per-install part is the *suffix*, so the prefix is a stable literal — and it
is set only for an authenticated user and cleared on logout.

**But it only exists for users who ticked "Remember Me."** A member who simply logs
in and does not tick the box carries **no such cookie**. What they carry is the
session cookie — and **that** has no fixed name. Joomla derives it from the site's
secret: on Joomla 4/5 the session name is `md5($secret . $seed)` where `$seed` is the
configured `session_name` or, by default, the application class
(`Joomla\CMS\Application\SiteApplication`) — see
[`libraries/src/Service/Provider/Session.php`](https://github.com/joomla/joomla-cms/blob/5.4-dev/libraries/src/Service/Provider/Session.php)
`generateSessionName()`. (Joomla 3.x used the older double hash `md5(md5($secret . 'site'))`;
the seed changed, but the result is the same shape.) Either way it is a bare 32-hex
cookie name with **no stable prefix**:

```
1a79a4d60de6718e8e5b326e338ae533=abc123...      # a real Joomla session cookie
```

(The front end and the administrator get *different* hashes — the seed is the
`SiteApplication` vs `AdministratorApplication` class, so the two areas never share a
cookie name.)

That name is different on every install, so there is no substring the module could
ship that would match your site and not somebody else's. WordPress can ship
`wordpress_logged_in_` because WordPress *prefixes* its hash; Joomla does not — the
whole name **is** the hash.

**So a normally-logged-in frontend user is invisible to this preset.** Do not read
the presence of a cookie row as "Joomla is handled."

## If your site has frontend logins, you MUST add a bypass

Find your install's session-cookie name (log in, then look at the `Cookie` header —
it is the bare 32-hex one), and bypass on it:

```nginx
# 1a79a4d6... is YOUR site's hash. It will not be the same as anyone else's.
cache_turbo_bypass $cookie_1a79a4d60de6718e8e5b326e338ae533;
```

Without that, the only things standing between a logged-in Joomla user and a
cached page are the `/administrator/` URI rule (which does not cover the front
end) and Joomla's own `Cache-Control` — and the core System - Page Cache plugin only
stores a page when `$app->getIdentity()->guest` is true (its `appStateSupportsCaching()`
also requires the site application, a `GET` request, and an empty message queue — see
[`plugins/system/cache/src/Extension/Cache.php`](https://github.com/joomla/joomla-cms/blob/5.4-dev/plugins/system/cache/src/Extension/Cache.php)),
which tells you upstream considers login state the thing that matters.
`joomla_remember_me_` raises the floor. It does not make
the preset safe on its own.

**Consequence:** `cache_turbo_backend joomla;` on its own gives you an admin-URI
guard and nothing more. A front-end user who logs in gets a session cookie the
module doesn't recognise, so their personalised page is a cache candidate like
any other. You must add the bypass yourself.

The universal floors still apply — a response with `Set-Cookie` is never stored,
and a request with `Authorization` is never cached — so the *login response*
itself won't be captured. But a subsequent page load by an already-logged-in user
carries only the session cookie and no `Set-Cookie`, and that one **will** be
cached unless you bypass it.

## Finding your session cookie

Log in to the front end and look at what Joomla set:

```bash
curl -sI -c - https://example.com/index.php?option=com_users \
  | awk '/Set-Cookie/ {print $2}'
```

Or just read it out of your browser's dev-tools. You're looking for the
32-hex-character cookie name. Then:

```nginx
cache_turbo_bypass $cookie_1a79a4d60de6718e8e5b326e338ae533;
```

If you'd rather not hard-code a hash that changes when the site secret is rotated,
match it with a `map` on the whole `Cookie` header instead:

```nginx
map $http_cookie $joomla_session {
    default              "";
    "~[0-9a-f]{32}="     "1";     # any 32-hex-named cookie = a Joomla session
}
```

```nginx
cache_turbo_bypass $joomla_session;
```

That's blunter (it bypasses on *any* 32-hex cookie, including a guest session
Joomla may have set), which costs you some hit rate but never leaks. On a site
where Joomla issues a session to guests too, prefer the explicit cookie name.

## Vhost

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    map $http_cookie $joomla_session {
        default          "";
        "~[0-9a-f]{32}=" "1";
    }

    server {
        listen 443 ssl http2;
        server_name example.com;
        root /var/www/joomla;
        index index.php;

        location / {
            try_files $uri $uri/ /index.php?$args;
        }

        location ~ \.php$ {
            cache_turbo               ct;
            cache_turbo_backend       joomla;

            # NOT OPTIONAL. The preset ships no cookie rule (see docs).
            cache_turbo_bypass        $joomla_session;
            cache_turbo_no_store      $joomla_session;

            cache_turbo_valid         60s;
            cache_turbo_valid         404 410 1m;
            cache_turbo_preset        balanced;

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

## Vhost + Redis L2

In `http`:

```nginx
cache_turbo_redis redis://10.0.0.5:6379/0 prefix=joomla: timeout=250ms
                  keepalive=32 keepalive_timeout=60s;
```

Joomla also has its own object/page caching (Global Configuration → System →
Cache) which is a different layer entirely — it caches Joomla's internal work,
inside PHP. Leave it on; it makes the origin fast, which is what your cache-turbo
misses hit. If you point Joomla's cache at the same Redis, give cache-turbo a
different DB number or `prefix=` so a `?all=1` purge doesn't clear both.

## Checking it works

```nginx
add_header X-Cache-Turbo $cache_turbo_status always;
```

```bash
# anonymous article: MISS then HIT
curl -sI https://example.com/index.php/blog/article | grep -i x-cache-turbo
curl -sI https://example.com/index.php/blog/article | grep -i x-cache-turbo  # HIT

# admin: BYPASS (this is all the preset gives you)
curl -sI https://example.com/administrator/ | grep -i x-cache-turbo

# THE ONE THAT MATTERS: a logged-in front-end user must be BYPASS.
# If this says HIT/MISS, your cache_turbo_bypass is wrong and you are one
# request away from serving a member's page to the public.
curl -sI -H 'Cookie: 1a79a4d60de6718e8e5b326e338ae533=abc' \
     https://example.com/index.php/blog/article | grep -i x-cache-turbo      # BYPASS
```

Run that last check against your **actual** session cookie name before you go
live. It is the whole safety story on Joomla.

## Kunena (Joomla forum component): same unshippable shape, no separate preset

Kunena is a Joomla **component**, not a standalone app — it has no auth/session
subsystem of its own. It runs entirely inside Joomla core's identity/session
layer (`JFactory::getApplication()->getIdentity()`, Joomla's `#__session` DB
table), so every cookie a Kunena forum visitor carries is a Joomla-core
cookie, exactly as described above. There is no Kunena-specific `setcookie()`
call, session cookie name, or cookie helper anywhere in its source — **do not
add a `kunena` preset bit**, it would be exactly as unshippable as a bare
`joomla` identity guard and would add nothing this page doesn't already cover.

Use the `joomla` preset plus your own per-install `cache_turbo_bypass` on your
site's session cookie (see above), and add Kunena's own always-dynamic
surfaces as extra URI-prefix bypasses — these are unauthenticated-cookie-
invisible actions that must never be served from cache regardless of cookie
state:

```nginx
cache_turbo_bypass_uri
    /index.php?option=com_kunena&view=user&layout=messages   # private messages
    /index.php?option=com_kunena&view=topic&layout=post;      # posting/reply
```

(Adjust for SEF URLs if enabled — match your site's actual routed paths for
these views.) Moderation actions under `/administrator/` are already covered
by the preset's admin-URI rule.

## Gotchas

- **The preset does not cover logged-in users.** Said three times because it's the
  one real footgun here. `cache_turbo_backend joomla;` without a
  `cache_turbo_bypass` for your session cookie is not a safe config.
- **Rotating the site secret changes the cookie name** — and silently breaks a
  hard-coded `$cookie_<hash>` bypass. Use the `map` form, or re-check after any
  secret rotation.
- **SEF URLs vary wildly.** With SEF off you get `/index.php?option=com_content&…`;
  with it on, arbitrary paths. The `/administrator/` prefix is stable either way,
  but any custom bypass you write must match your actual URL scheme.
- **Third-party components** (VirtueMart carts, membership extensions) add their
  own private surfaces and their own cookies. The preset knows nothing about them.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached, regardless of preset. Those floors hold.
- **Do not rely on `joomla_user_state` as a fixed-name login flag.** Third-party
  cookie databases describe a `joomla_user_state` cookie "set when logged in, deleted
  on logout" — but that string does not appear anywhere in Joomla 5 core source
  (unverified / community-reported, likely an older-version or extension artifact). It
  is not a stable, shippable auth cookie; the session cookie (32-hex) and
  `joomla_remember_me_` remain the only login signals to key on.

## PHP settings / gotchas

Joomla-specific PHP notes. General PHP-FPM tuning lives with the other presets;
these are the things that bite on Joomla in particular.

- **The session cookie name is an MD5 hash and differs per site.** Joomla runs on
  native PHP sessions, and its session/cookie name is `md5($secret . $seed)` (Joomla
  4/5; see the cookie section above). There is no fixed string to ship, so the preset
  and every example here key on cookie **presence** — the `~[0-9a-f]{32}=` `map` — not
  on a known name. Rotating the site secret (or changing `session_name`) changes the
  name; the `map` survives that, a hard-coded `$cookie_<hash>` does not.
- **The System - Page Cache plugin is a second cache layer — mind double-caching.**
  It caches whole rendered pages inside PHP for guests only (see above), so it and
  cache-turbo can both hold a copy of the same URL. That is fine for hit-rate, but its
  **`browsercache`** parameter (default `0`/off) makes Joomla emit `Cache-Control` /
  `Expires` headers to the *client*; turning it on hands browsers and any downstream
  proxy their own freshness window that you cannot purge when you flush cache-turbo.
  Leave `browsercache` off and let the nginx layer own the full-page cache and its
  invalidation. (Joomla core has a long history of emitting conservative
  `Cache-Control: no-cache` / stale `Expires` headers otherwise.)
- **Enable opcache.** A stock Joomla plus a normal extension set loads a large number
  of PHP class files per request; opcache is the single biggest origin-speed win for
  the misses cache-turbo passes through.
- **`memory_limit` for large extension sets.** Component-heavy sites (page builders,
  VirtueMart, multilingual) and the extension installer are memory-hungry — 128M is a
  floor, 256M is realistic for a busy install.
- **`max_execution_time` for `com_installer` and the cache-clean cron.** Installing or
  updating extensions via `com_installer`, and Joomla's scheduled cache/expired-session
  cleanup, can run well past the default 30s. Raise the limit for those paths (the CLI
  scheduler in particular), not for normal page requests.
- **Joomla keeps its own cache directories.** `cache/` (front end) and
  `administrator/cache/` are Joomla's internal caches, entirely separate from
  cache-turbo's store. Clearing Joomla cache (System → Clear Cache) does not touch
  cache-turbo, and a cache-turbo purge does not clear these — flush both layers when
  content changes. If the session handler is set to the filesystem, session GC lives
  here too.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [README — per-request opt-outs](../README.md#the-cache-key)
- [`docs/README.md`](README.md) — all presets
