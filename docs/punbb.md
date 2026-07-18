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

The `punbb` preset matches two substrings of the `Cookie` header — the search is
raw and undelimited over names *and* values, not a cookie-name lookup, so a
literal must be distinctive enough that it cannot appear as an arbitrary value.
Both of these are: **`forum_cookie`**, the
PunBB 1.4.x default (verify: `include/common.php` in punbb/punbb, tag 1.4.4 —
`$cookie_name` in `config.php` falls back to it, and the installer randomises
it to `forum_cookie_<random>`, which the same substring still covers), and
**`punbb_cookie`**, the older 1.2-era default that upgraded boards still carry.
A stock 1.4.x install therefore works out of the box. Only an operator who has
renamed `$cookie_name` to something matching neither needs to act — see PHP
settings — otherwise member requests are never bypassed, because the preset's
names are simply absent from the `Cookie` header.

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

So this ships as **presence-only**: the preset substring-matches the request
`Cookie` header, bypassing whenever anything containing
`forum_cookie` or `punbb_cookie` is present. Safe (bypass is the
correct-direction failure), and the hit-rate cost is smaller than it looks:
PunBB's `<cookie_name>_track` topic-tracking cookie shares the prefix and trips
the same substring match, but it is **members-only** — every
`set_tracked_topics()` call site is guest-gated (`viewtopic.php` wraps it in
`if (!$forum_user['is_guest'])`; `misc.php`'s mark-read actions reject guests
outright), so a browsing guest never acquires it and stays cacheable.

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
- **A renamed `$cookie_name` defeats the preset.** The defaults
  (`forum_cookie`, the installer's `forum_cookie_<random>`, and the 1.2-era
  `punbb_cookie`) are all matched; anything else is not. Add a
  `cache_turbo_bypass $cookie_<your_name>;` **plus**
  `cache_turbo_no_store $cookie_<your_name>;` for a custom name — otherwise
  logged-in members are served cached pages. The bypass alone only skips the
  lookup; the `no_store` is the half that stops the member's page being stored.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached, regardless of preset.

## PHP settings / gotchas

PunBB-specific only; generic PHP-FPM tuning lives in the other backend guides.

- **`$cookie_name` must line up with the preset.** This is the load-bearing
  signal. The `punbb` preset substring-matches `forum_cookie` (the 1.4.x
  default, which also covers the installer's `forum_cookie_<random>`) and
  `punbb_cookie` (the 1.2-era default kept for upgraded boards). A stock
  install needs no change. If you have set `$cookie_name` in `config.php` to
  anything else, the preset sees nothing and **every member is served cached
  pages** — add your own `cache_turbo_bypass $cookie_<your_name>;` and
  `cache_turbo_no_store $cookie_<your_name>;` (the bypass alone still stores). The
  `<cookie_name>_track` topic-tracking cookie shares the prefix and also trips
  the substring match — but it is written only for logged-in members
  (`set_tracked_topics()` is guest-gated at every call site), so it costs no
  guest hit rate.
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
  covers `admin/`, `login.php`, `post.php`, `edit.php`, `delete.php`,
  `moderate.php`, `profile.php`, `register.php` and `misc.php`; PunBB
  guards these in PHP too (`admin/*` checks `$forum_user['g_id'] != FORUM_ADMIN`),
  so a cached admin page is never a risk even if a URI is missed — the member
  cookie already forces BYPASS.
- **There is no PM row, because PunBB core has no PM.** Private messaging is a
  third-party extension; core's user-to-user surfaces are the email-a-user and
  report-a-post forms inside `misc.php`, which the list already covers. If your
  board runs a PM extension, add its own path yourself:
  `cache_turbo_bypass_uri /pm/;` (or whatever the extension routes on).
- **1.2-era boards get no admin URI rule.** The list matches `admin/`, the
  1.4.x layout. PunBB 1.2 put `admin_index.php`, `admin_users.php`, … at the
  document root, and the URI matcher requires a `/` or `.` immediately after the
  needle — so a shorthand like `/admin_` cannot be expressed. This is safe
  rather than merely tolerated: reaching any admin page requires being logged
  in, and the cookie rule bypasses every logged-in request already. Upgrade
  regardless; 1.2 has been end-of-life since 2013.
- **opcache on.** PunBB is a many-small-includes codebase (`include/` +
  per-page scripts); `opcache.enable=1` with a generous
  `opcache.max_accelerated_files` pays off. On cache-turbo HITs PHP is skipped
  entirely, so opcache matters most for the BYPASS (member/admin) traffic.
- **memory_limit / max_execution_time.** PunBB is light — 32–64M is plenty.
  Default `max_execution_time = 30` is fine; the only slow endpoints are
  `admin/reindex.php`, which the preset bypasses, and `search.php`, which it
  does NOT — search is a guest-reachable read surface and caches normally, so
  a raised limit there widens the cacheable surface rather than the bypassed
  one. Vary the key on the query string (the default key already does) and let
  repeated searches HIT.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/phpbb.md`](phpbb.md) — the same shape, and the same engine limitation
- [`docs/README.md`](README.md) — all presets
