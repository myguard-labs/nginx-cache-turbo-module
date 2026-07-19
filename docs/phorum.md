# Phorum + cache-turbo

_Last researched: 2026-07-18_

Caching a Phorum board. The clean case: presence alone is a safe, sufficient
signal, no value predicate, no per-install hash.

- [The short version](#the-short-version)
- [Why presence alone is safe here](#why-presence-alone-is-safe-here)
- [Vhost](#vhost)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)
- [PHP settings / gotchas](#php-settings--gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend phorum;
```

## Why presence alone is safe here

Phorum's session cookies (`phorum_session_v5` long-term, `phorum_session_st`
short-term, `phorum_admin_session` admin — the `PHORUM_SESSION_LONG_TERM` /
`PHORUM_SESSION_SHORT_TERM` / `PHORUM_SESSION_ADMIN` constants in
`include/api/user.php`, fixed literals rather than per-install hashes or
admin-configurable prefixes) are written **only** by
`phorum_api_user_session_create()`, called only from a successful login (the
short-term cookie only when `tight_security` is enabled — see below). This is
the inverse of the XenForo/Discourse/phpBB/Flarum trap: a guest never receives
any of these cookies, so presence is a correct, sufficient bypass signal on its
own. The long-term `phorum_session_v5` cookie (value `user_id:sessid`) is the
load-bearing member signal.

> Verified against Phorum `Core` at v6.0.3 (`include/api/user.php` lines 61–74,
> `common.php:88`), 2026-07-18.

`phorum_tmp_cookie` **is** guest-issued — a one-shot cookie-support probe with
no identity value, destroyed on login — and is deliberately absent from the
rule.

Phorum is a flat top-level-script app (`admin.php`, `login.php`, ... — no path
hierarchy), so the dynamic surface is a set of script-name prefixes, not
`/paths/`.

## Vhost

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    server {
        listen 443 ssl http2;
        server_name forum.example.com;
        root /var/www/phorum;
        index index.php;

        location / {
            try_files $uri $uri/ /index.php?$args;
        }

        location ~ \.php$ {
            cache_turbo               ct;
            cache_turbo_backend       phorum;

            # Phorum's own thread-display style is presentation, not identity —
            # the `phorum` preset already folds `list_style` into the key with
            # length-prefixed framing. Do NOT hand-write a cache_turbo_key that
            # splices $cookie_* values together: unframed concatenation lets a
            # visitor choose a cookie value that reproduces another page's key.
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

## Checking it works

```nginx
add_header X-Cache-Turbo $cache_turbo_status always;
```

```bash
# guest thread: MISS then HIT
curl -sI https://forum.example.com/read.php?1,1 | grep -i x-cache-turbo
curl -sI https://forum.example.com/read.php?1,1 | grep -i x-cache-turbo  # HIT

# THE ONE THAT MATTERS: a logged-in member must be BYPASS.
curl -sI -H 'Cookie: phorum_session_v5=42:abcdef' \
     https://forum.example.com/read.php?1,1 | grep -i x-cache-turbo      # BYPASS

# admin: BYPASS
curl -sI https://forum.example.com/admin.php | grep -i x-cache-turbo
```

## Gotchas

> **Subdirectory installs.** This preset's URI rules are root-relative literals
> matched from byte 0 of `r->uri`, so an install mounted under a subdirectory
> (`/shop/`, `/forum/`, …) matches **none** of them — the admin surface
> included. Declare the mount with `cache_turbo_backend_prefix /forum/;` and the
> preset URI tier is compared against the rebased path. Scoping the nginx
> `location` does **not** substitute: it routes requests, it does not rewrite
> `r->uri`. See [frameworks.md](frameworks.md).

- **`list_style` (threaded/flat/hybrid) is presentation, not identity** — fold
  it into the key (as the vhost above does) rather than bypassing on it.
- **`phorum_tmp_cookie` is guest-issued** and must never be added to a bypass
  rule — it carries no identity, matching it is a pure hit-rate loss.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached, regardless of preset.
- **Admin protection is by URI, not by cookie.** `/admin.php` is in the
  preset's URI-bypass list, so the backend is BYPASS by path even if the admin
  cookie is renamed or absent. Don't rely on the admin *cookie* alone to gate
  the cache.
- **Attachments (`/file.php`) are bypassed by URI, and must be.** `file.php`
  authorises every download through the file-storage API: a file attached to a
  message in a read-restricted forum is refused to anyone without access. That
  check lives behind the request, so a cached `file.php?file=<id>` response
  would hand the first requester's attachment to every later requester of the
  same id with the permission check skipped. The row is in the preset; if you
  hand-write a URI list instead of using `cache_turbo_backend phorum`, do not
  omit it.

## PHP settings / gotchas

Phorum-specific. Phorum is plain PHP with its own MySQL layer; these bite
whether or not cache-turbo is in front.

- **The login signal is the session cookie, not a PHP session.** Phorum does
  not use PHP's native `$_SESSION` for member state — it issues its own
  `phorum_session_v5` (long-term) cookie on login. Presence of that cookie is
  the sole logged-in-member signal the preset needs; a guest never carries it.
- **`tight_security` = the short-term cookie mode.** With the tighter
  authentication scheme enabled (`$PHORUM['tight_security']`), Phorum adds a
  second, shorter-lived cookie `phorum_session_st` (value `user_id:sessid_st`,
  32-byte random id, TTL `short_session_timeout`) alongside the long-term one.
  The preset matches both, so tight-security installs bypass correctly with no
  config change. The short-term cookie is issued only in this mode and only via
  cookies (URI-authentication installs skip it).
- **`/admin.php` is never cacheable.** The admin backend is dynamic per request
  and gated by the `phorum_admin_session` cookie; the preset bypasses it by URI
  (`admin.php`) rather than trusting the cookie name, which is the robust move.
- **UNMAINTAINED-project caveat — pin your PHP version.** Phorum sat dormant for
  roughly nine years: the 5.2.x line's last public release was 5.2.23 (2016),
  and the tree was quiet from January 2017. A 6.0.x line appeared in early July
  2026 (tags `v6.0.0`–`v6.0.3`, commit "PHP 8.2 modernization and security
  hardening") that **requires PHP 8.2 or higher** (`README.md`, "PHP, version
  8.2 or above"). The revival is brand-new and its longevity is
  unverified/community-reported. Practical consequence for the whole
  deployment: legacy **Phorum 5.2.x will not run clean on PHP 8.x** (PHP 4-style
  constructors, deprecated/removed functions). Running 5.2.x means an
  end-of-life PHP 7.x FPM pool — **not a supported deployment target**, only a
  migration-window stopgap: isolate that pool (no shared FPM with anything else
  internet-facing, no known-unpatched CVEs left open) while you move to 6.0.x on
  PHP 8.2+, the only currently-supported combination. Pin the FPM version to the
  Phorum version you actually run — a silent PHP upgrade is what breaks an
  abandoned board. This affects the application, not the cache layer; cache-turbo
  simply serves whatever the backend returns.
- **`opcache`** — enable it. Phorum's front controllers (`read.php`, `list.php`,
  `index.php`, …) are recompiled on every request otherwise; with cache-turbo
  absorbing guest hits, the opcache mainly benefits the uncached member and
  write traffic.
- **`memory_limit`** — Phorum is modest; the stock 128M is comfortable. Raise
  it only for large PM mailboxes, bulk moderation, or big attachment handling
  via `file.php`.
- **`max_execution_time`** — keep the default (~30s). Long-running work is the
  installer/upgrader and full-text `search.php` on large boards; bump it
  temporarily for an upgrade rather than globally. None of these paths are
  cached, so a raised limit does not widen the cacheable surface.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/README.md`](README.md) — all presets
