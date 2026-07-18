# PunBB + cache-turbo

_Last researched: 2026-07-18_

Caching a PunBB board. Same guest-issued-cookie shape as phpBB/SMF; this
preset ships presence-only, trading hit rate for an engine limitation — read
why below before assuming the sharper rule is active.

- [The short version](#the-short-version)
- [Why presence-only (not the value predicate)](#why-presence-only-not-the-value-predicate)
- [Vhost](#vhost)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend punbb;
```

## Why presence-only (not the value predicate)

The `punbb` preset keys on a cookie named `punbb_cookie`, but that is **not**
the current PunBB default (verify: `include/common.php` in punbb/punbb, tag
1.4.4). On PunBB 1.4.x the auth cookie is `$cookie_name` from `config.php`,
which falls back to **`forum_cookie`** and is randomised to
`forum_cookie_<random>` by the installer (`admin/install.php`); `punbb_cookie`
is the older 1.2-era default the preset still anchors on. Line these up first
(see PHP settings) or member requests are never bypassed — the preset's name
simply won't be present in the `Cookie` header.

Unlike phpBB, PunBB does **not** write the auth cookie to every fresh guest.
`cookie_login()` (`include/functions.php`) only (re)issues `$cookie_name` for a
returning member (`user_id > 1`) or transiently on logout; `set_default_user()`
writes no cookie at all, and `FORUM_QUIET_VISIT` gates only the online-list
update, not any cookie write. A pure guest therefore carries the auth cookie
only after having once been logged in. Its value is a base64'd, pipe-delimited
4-field string whose **first field is the numeric user_id directly**: a guest's
is the hardcoded literal `1` (`login.php`'s logout path and `cookie_login()`'s
downgrade branch both write
`base64_encode('1|'.random_key(8,false,true).'|'.$expire.'|'.random_key(...))`);
a real login writes the actual (never-1) user_id.

In principle that is even cleaner than phpBB's derived `_u` flag — a bare
numeric field, not something computed. In practice, this module's cookie-value
engine compares the **raw wire value** against a fixed literal (or tests
non-emptiness); it does not base64-decode. PunBB's guest value has a random
key suffix after `1|`, so it is never one fixed string an exact-match test can
anchor on — the ideal rule is not expressible without adding a base64 decoder
to the hot classify path, which no preset here does.

So this ships as **presence-only**: the preset substring-matches the cookie
**name** in the request `Cookie` header, bypassing whenever anything containing
`punbb_cookie` is present. Safe (bypass is the correct-direction failure), but
PunBB also sets a `<cookie_name>_track` topic-tracking cookie for guests who
read topics (`set_tracked_topics()`) — it shares the prefix and trips the same
substring match, so an actively-browsing guest stops being cached.

## Vhost

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    server {
        listen 443 ssl http2;
        server_name forum.example.com;
        root /var/www/punbb;
        index index.php;

        location / {
            try_files $uri $uri/ /index.php?$args;
        }

        location ~ \.php$ {
            cache_turbo               ct;
            cache_turbo_backend       punbb;

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
# guest topic: MISS then HIT
curl -sI https://forum.example.com/viewtopic.php?id=1 | grep -i x-cache-turbo
curl -sI https://forum.example.com/viewtopic.php?id=1 | grep -i x-cache-turbo  # HIT

# THE ONE THAT MATTERS: a logged-in member must be BYPASS.
curl -sI -H 'Cookie: punbb_cookie=NDJ8c29tZWhhc2h8MTIzNDU2fGFiYw==' \
     https://forum.example.com/viewtopic.php?id=1 | grep -i x-cache-turbo     # BYPASS

# admin/posting: BYPASS (1.4.x admin lives under admin/, not admin.php)
curl -sI https://forum.example.com/admin/index.php | grep -i x-cache-turbo
curl -sI https://forum.example.com/misc.php?action=markread | grep -i x-cache-turbo
```

## Gotchas

- **Presence-only, not the ideal value predicate.** See above — accept the
  hit-rate cost, or run PunBB behind an app that can decode the cookie
  upstream and set a simpler signal cache-turbo can key on instead.
- **The preset's `punbb_cookie` is not the 1.4.x default.** `$cookie_name`
  defaults to `forum_cookie` (installer randomises it to
  `forum_cookie_<random>`); set it to `punbb_cookie` in `config.php`, or add a
  `cache_turbo_bypass $cookie_<your_name>;` for the real name — otherwise
  logged-in members are served cached pages.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached, regardless of preset.

## PHP settings / gotchas

PunBB-specific only; generic PHP-FPM tuning lives in the other backend guides.

- **`$cookie_name` must line up with the preset.** This is the load-bearing
  signal. The `punbb` preset substring-matches the literal `punbb_cookie`, but a
  stock 1.4.x install writes `forum_cookie` (or the installer's
  `forum_cookie_<random>`). On such an install the preset sees nothing and
  **every member is served cached pages**. Either set
  `$cookie_name = 'punbb_cookie';` in `config.php`, or leave the default and add
  your own `cache_turbo_bypass $cookie_<your_name>;`. The `<cookie_name>_track`
  topic-tracking cookie shares the prefix and also trips the substring match.
- **Guest = user id 1.** PunBB's anonymous user is the row with `id = 1`
  (`set_default_user()` hard-requires it), and the auth cookie's first base64
  field is that id. The preset can't base64-decode on the hot path, so it keys
  on cookie *presence*, not the decoded id — see "Why presence-only" above.
- **PunBB's own `cache/` dir is not the nginx layer.** `FORUM_CACHE_DIR`
  (`cache/`, holding `cache_config.php`, `cache_bans.php`, `cache_ranks.php`,
  `cache_censors.php`, …) is PunBB's PHP-side fragment cache and must stay
  writable by PHP. It is orthogonal to cache-turbo's full-page store — never
  point the nginx zone at it, and clearing one does not clear the other.
- **Admin / posting / login stay dynamic.** The preset's never-cache URI list
  covers `admin/`, `login.php`, `post.php`, `misc.php` and the PM scripts; PunBB
  guards these in PHP too (`admin/*` checks `$forum_user['g_id'] != FORUM_ADMIN`),
  so a cached admin page is never a risk even if a URI is missed — the member
  cookie already forces BYPASS.
- **opcache on.** PunBB is a many-small-includes codebase (`include/` +
  per-page scripts); `opcache.enable=1` with a generous
  `opcache.max_accelerated_files` pays off. On cache-turbo HITs PHP is skipped
  entirely, so opcache matters most for the BYPASS (member/admin) traffic.
- **memory_limit / max_execution_time.** PunBB is light — 32–64M is plenty.
  Default `max_execution_time = 30` is fine; the only slow endpoints are
  `admin/reindex.php` and search, which are bypassed anyway.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/phpbb.md`](phpbb.md) — the same shape, and the same engine limitation
- [`docs/README.md`](README.md) — all presets
