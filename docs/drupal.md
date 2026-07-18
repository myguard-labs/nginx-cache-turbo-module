# Drupal + cache-turbo

_Last researched: 2026-07-18_

Caching a Drupal 9/10/11 site. The Drupal preset ships the **`SESS` cookie rule**
— it bypasses the cache for any request carrying a Drupal session cookie. Read
[why](#the-preset-ships-the-sess-cookie-rule) so you know what it protects and
what it costs.

- [The short version](#the-short-version)
- [The preset ships the `SESS` cookie rule](#the-preset-ships-the-sess-cookie-rule)
- [Belt and braces](#belt-and-braces)
- [Vhost](#vhost)
- [Vhost + Redis L2](#vhost--redis-l2)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)
- [PHP settings / gotchas](#php-settings--gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend drupal;      # implies cache_turbo_cache_control honor
```

That is genuinely all most sites need. The preset bypasses the cache for any
request carrying Drupal's `SESS` session cookie, and its URI rules cover the
surfaces that are dynamic *before* any cookie exists. As defence-in-depth,
`cache_turbo_backend` implies `cache_turbo_cache_control honor`, and Drupal sends
`Cache-Control: private, must-revalidate` on every authenticated response — which
`honor` refuses to store.

## The preset ships the `SESS` cookie rule

| Check | Values |
|---|---|
| URI prefixes | `/user`, `/admin`, `/node/add`, `/system/`, `/core/install.php` |
| Query args | — |
| Cookie substrings | `SESS` |

Drupal's session cookie is `SESS<32-hex>` — or `SSESS<32-hex>` over TLS — where
the hash is the first 32 chars of a SHA-256 derived per-install from the site's
hostname and base path (`Core/Session/SessionConfiguration::getUnprefixedName()`,
prefix chosen by `getName()` on `$request->isSecure()`). There is no stable suffix, so the only
literal the module can ship is the leading `SESS` — which, as a substring, covers
both the plain and the TLS form in one rule.

## This preset used to ship no cookie rule. That was a leak.

The old reasoning went: `SESS` is a substring of `PHPSESSID` and `JSESSIONID`, so
shipping it would bypass on any co-hosted PHP or Java app's session cookie and
zero *their* hit rate — and anyway Drupal defends itself with `Cache-Control:
private`, so the cookie rule is unnecessary. **Both halves of that were wrong in a
way that mattered.**

**Anonymous Drupal users DO get a session cookie.** The old comment assumed they
never do. Drupal opens a session for an anonymous visitor as soon as *anything*
writes to `$_SESSION`, and core's own `NoSessionOpen` docblock names the everyday
cases: a **status message queued by a form submission**, and **cart contents**. So
`SESS<hash>` is not a logged-in-only marker in one direction — but a **logged-in
user carries exactly the same cookie shape**. With no cookie rule at all, nothing
in the request identifies that member, and their authenticated page is a candidate
for storage.

**And the Cache-Control floor is not something correctness may rest on.** Yes,
`FinishResponseSubscriber` sets `private, must-revalidate` on authenticated
responses, and `honor` mode (which `cache_turbo_backend` implies) refuses to store
`private`. But `cache_turbo_cache_control ignore` **switches that floor off**, and
this project's own README recommends that mode for origins that blanket everything
with `max-age=0`. An operator who follows that advice on a Drupal site was, under
the old preset, one config line away from serving a logged-in user's page to a
stranger. A bypass rule must hold on its own.

## The collision is real, and it is the accepted price

`SESS` genuinely does match inside `PHPSESSID` and `JSESSIONID`:

```
PHPSESSID=...      <- every stock PHP app     -> also bypasses
JSESSIONID=...     <- every stock Java app    -> also bypasses
```

If you co-host another PHP or Java app under the same `server` block, its session
cookie will bypass cache-turbo too. **That is a hit-rate loss on that app. It is
never a leak.** And a hit-rate loss on a neighbouring app is not a reason to keep
leaking on the Drupal one — so the rule ships.

If the collision costs you, narrow it to your install:

```nginx
# Replace <hash> with the value from your own Set-Cookie (see the 3-curl check).
cache_turbo_bypass $cookie_SESS<hash>;
```

## Not `NO_CACHE`

`NO_CACHE` looks like the obvious addition — it is a fixed literal, and it appears
in every canonical Drupal VCL. Do not add it:

- It is **contrib, not core** (zero hits in the Drupal 11 `core/` tree). It is
  Pressflow/Varnish heritage, carried by modules like `cookie_cache_bypass_adv`.
- It is set **for logged-out visitors by design** — that is its entire purpose:
  force a cache bypass for a guest who must see fresh content.

Matching it would cost hits and buy no safety.

**The origin's `Cache-Control` is still there**, and still useful — it is now
defence-in-depth *behind* the cookie rule, which is the correct ordering.

## Belt and braces

The preset already bypasses on the `SESS` substring. If you want a **more
precise** request-side rule — one that matches Drupal's cookie shape without also
catching a co-hosted app's `PHPSESSID`, or because you run a contrib module that
writes to `$_SESSION` and emits pages Drupal marks cacheable — add your own. Find
the cookie name:

```bash
curl -sI -c - https://example.com/user/login | grep -i set-cookie
# Set-Cookie: SSESS9f2a4c1e...=abc123; path=/; secure; HttpOnly
#             ^^^^^^^^^^^^^^^^ this
```

Then either pin the exact name:

```nginx
cache_turbo_bypass $cookie_SSESS9f2a4c1e8b7d6f5a4c3b2a1908070605;
```

…or, better, match the shape without hard-coding a hash that changes if you move
the site to a new hostname:

```nginx
map $http_cookie $drupal_session {
    default                 "";
    "~S?SESS[0-9a-f]{32}="  "1";   # SESS<hash> or SSESS<hash>, Drupal-shaped
}
```

```nginx
cache_turbo_bypass   $drupal_session;
cache_turbo_no_store $drupal_session;
```

That pattern is specific enough not to hit `PHPSESSID` (which has no 32-hex tail),
which is exactly what the shipped preset cannot express with a plain substring.

## Vhost

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    map $http_cookie $drupal_session {
        default                "";
        "~S?SESS[0-9a-f]{32}=" "1";
    }

    server {
        listen 443 ssl http2;
        server_name example.com;
        root /var/www/drupal/web;
        index index.php;

        location / {
            try_files $uri /index.php?$query_string;
        }

        location ~ '\.php$|^/update.php' {
            cache_turbo               ct;
            cache_turbo_backend       drupal;   # implies cache_control honor

            # Optional -- Drupal's own Cache-Control already covers this.
            cache_turbo_bypass        $drupal_session;
            cache_turbo_no_store      $drupal_session;

            cache_turbo_valid         60s;
            cache_turbo_valid         404 410 1m;
            cache_turbo_preset        balanced;

            fastcgi_split_path_info ^(.+?\.php)(|/.*)$;
            include                 fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_pass  unix:/run/php/php-fpm.sock;
        }

        # Aggregated CSS/JS and public files: content-hashed, long-lived.
        location ~ ^/sites/.*/files/ {
            cache_turbo off;
            expires 30d;
            access_log off;
        }

        # Private file downloads are permission-checked per user -- never cache.
        location ^~ /system/files/ {
            cache_turbo off;
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
cache_turbo_redis redis://10.0.0.5:6379/0 prefix=drupal: timeout=250ms
                  keepalive=32 keepalive_timeout=60s;
```

Drupal's own cache backends (Internal Page Cache, Dynamic Page Cache) live inside
PHP and are a different layer. Leave them on — they make the origin fast, which is
what your cache-turbo misses hit. If you point Drupal's cache at the same Redis,
give cache-turbo a different DB number or `prefix=` so a `?all=1` purge doesn't
clear both.

## Checking it works

```nginx
add_header X-Cache-Turbo $cache_turbo_status always;
```

```bash
# anonymous node: MISS then HIT
curl -sI https://example.com/node/1 | grep -i x-cache-turbo
curl -sI https://example.com/node/1 | grep -i x-cache-turbo   # HIT

# preset URI surfaces: BYPASS
curl -sI https://example.com/user       | grep -i x-cache-turbo
curl -sI https://example.com/admin/config | grep -i x-cache-turbo

# THE ONE THAT MATTERS: a logged-in user must never be served from cache.
# Expect BYPASS -- the preset's SESS cookie rule catches the session cookie.
# (Even without it, Drupal sends Cache-Control: private, so honor mode refuses
# to STORE the response -- but the cookie rule is what you rely on.) Never a HIT.
curl -sI -H 'Cookie: SSESS9f2a...=abc' https://example.com/node/1 \
     | grep -i x-cache-turbo

# Prove the origin really is sending private -- this is your safety net.
curl -sI -H 'Cookie: SSESS9f2a...=abc' https://example.com/node/1 \
     | grep -i cache-control
# Cache-Control: private, must-revalidate     <- if this is missing, ADD THE MAP
```

That last check is your defence-in-depth safety net. The `SESS` cookie rule is the
primary defence; Drupal sending `private` is the belt behind it. If a contrib
module or an aggressive "performance" setting has stripped `private`, the cookie
rule still holds — but add the `map` bypass too and don't lean on the origin.

## Gotchas

- **Think twice before `cache_turbo_cache_control ignore` on a Drupal site.** The
  `SESS` cookie rule still bypasses authenticated requests, but `ignore` switches
  off the `Cache-Control: private` floor that the `honor` implied by
  `cache_turbo_backend` gives you — you lose the belt behind the cookie rule.
- **`/user` and `/admin` are not reserved words.** They're ordinary Drupal routes,
  which is exactly why no preset is ever enabled implicitly — a non-Drupal site
  may serve `/user` as a perfectly cacheable page. Name the preset explicitly.
- **Contrib modules add their own private surfaces.** Commerce carts, Group,
  Private Message — the preset knows nothing about them. Add a
  `cache_turbo_bypass` for each.
- **`SESS` is shipped, and it is a substring.** Because the preset matches the
  bare literal `SESS`, it also catches `PHPSESSID` and `JSESSIONID` from any other
  PHP or Java app under the same `server` block — a hit-rate loss on that app,
  never a leak. If it costs you, narrow it with the `map` form above or a
  `cache_turbo_bypass $cookie_SESS<your-hash>;` scoped to your install.
- **`/core/install.php` and `/update.php`** are dynamic; the preset covers the
  former, and the vhost above routes the latter through the same PHP block.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached, regardless of preset. Those floors hold.

## PHP settings / gotchas

These are the Drupal-specific PHP/PHP-FPM knobs that change how the preset behaves.
Generic tuning belongs in your PHP-FPM docs; only the Drupal interactions are here.

- **The session cookie is the signal — don't defeat it.** Drupal uses PHP's native
  session handler and *renames* the cookie itself via `SessionConfiguration`
  (`SESS<hash>` / `SSESS<hash>` over TLS), so a stray `session.name` in `php.ini`
  is overridden and does not change what the preset matches. What matters is that
  the cookie is present exactly when a session exists — which is the logged-in (and
  cart-carrying anonymous) signal the `SESS` rule bypasses on. Don't front Drupal
  with anything that strips or rewrites the `Set-Cookie` / `Cookie` on PHP requests,
  or the bypass loses its input.

- **opcache is effectively mandatory, and Drupal is file-heavy.** Drupal's status
  report warns when opcache is off, and the codebase is large (a stock Drupal 11
  plus a few contrib modules runs well past 15,000 PHP files). Set
  `opcache.max_accelerated_files` to ~`20000` so every file stays cached — the
  common `10000` default silently evicts, and a half-cached opcode table is slow
  origin, which is what every cache-turbo MISS pays for. In production also set
  `opcache.validate_timestamps=0` (and reload PHP-FPM on deploy) for the fastest
  path; `opcache.interned_strings_buffer=16` and `opcache.memory_consumption>=192`
  suit a real Drupal build.

- **`memory_limit` 256M or more.** Drupal recommends 256M+; the admin UI, batch
  API, `update.php`, and Composer/media operations routinely exceed the PHP default.
  An OOM here surfaces as a 500 that cache-turbo will not store (`honor` refuses a
  non-2xx/`private` response), so it is never *served* stale — but it is still a bad
  page. Size the pool for it.

- **`max_execution_time` for `cron.php` and `update.php`.** Both can run long
  (entity updates, index rebuilds). The vhost above routes `/update.php` through the
  same PHP block, so the FPM `request_terminate_timeout` and PHP `max_execution_time`
  bound it — raise them for those routes or, better, run cron and database updates
  from the CLI (`drush cron`, `drush updatedb`) where no web timeout applies. These
  routes are never cached regardless.

- **Drupal's own `max-age` meets `honor` mode.** `cache_turbo_backend drupal`
  implies `cache_turbo_cache_control honor`, so the module reads Drupal's
  `Cache-Control` when deciding whether to store. Core's Internal Page Cache emits
  `Cache-Control: max-age=<N>, public` on cacheable anonymous pages, where `<N>` is
  the **Browser and proxy cache maximum age** setting
  (`system.performance:cache.page.max_age`, `/admin/config/development/performance`).
  On many installs that value is `0` — Drupal then emits `max-age=0`, and `honor`
  will refuse to **store** the response no matter what `cache_turbo_valid` says:
  the storage veto runs first, and an explicit TTL only ever applies to a response
  that already cleared it — `cache_turbo_valid` is the fallback TTL for a response
  with no freshness header at all, not an override for `max-age=0`. Either set
  that value above zero, or explicitly set `cache_turbo_cache_control` to
  something other than `honor` for this location. Note that a bare `s-maxage` is
  *contrib* (`http_cache_control` / `cache_control_override`), not core — don't
  assume it's present.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/mediawiki.md`](mediawiki.md) — a preset that leans on origin `Cache-Control`
- [`docs/phpbb.md`](phpbb.md) — a preset with no cookie rule and *no* origin safety net
- [`docs/README.md`](README.md) — all presets
