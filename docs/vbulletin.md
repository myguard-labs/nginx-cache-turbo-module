# vBulletin + cache-turbo

_Last researched: 2026-07-18_

Caching a vBulletin board — vBulletin 5 Connect (current as of 2026-07) and the
vB4/vB3 legacy line, which share the same login-cookie shape (see the
[prefix note](#the-cookie-prefix-and-the-underscore) — the underscore in `bb_`
is not universal). Closed-source
commercial PHP, so no source read is possible; the cookie shape is documented in
the vBulletin manual and community forum and matches production LiteSpeed/nginx
guest-caching configs, so this ships with reasonable confidence.

- [The short version](#the-short-version)
- [Why presence/non-empty is safe here](#why-presencenon-empty-is-safe-here)
- [Vhost](#vhost)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)
- [PHP settings / gotchas](#php-settings--gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend vbulletin;
```

## Why presence/non-empty is safe here

`bbuserid` and `bbpassword` are the load-bearing signal. The vBulletin
community documents them as set **on login and removed on logout** — a guest
only ever carries `bblastactivity`, `bblastvisit`, and `bbsessionhash`.
Presence/non-empty-value alone is sufficient; no value-split trick needed.
(`bbimloggedin=yes` also appears in some LiteSpeed/nginx guest-cache configs as
an extra login flag, but it is community-reported and not in the official cookie
docs — treat it as belt-and-braces, not the primary signal.)

| Cookie | Treatment | Why |
|---|---|---|
| `bbuserid` / `bbpassword` (suffix `userid`/`password`) | **bypass** (non-empty) | set only on login, removed on logout |
| `bbimloggedin` == `yes` | **bypass** | community-reported extra login flag (LiteSpeed/nginx configs); not in official cookie docs |
| `bbsessionhash` | **ignore** | session tracking for every visitor including guests |
| `bblastvisit` / `bblastactivity` / language cookie | **cache key** (manual) | presentation, not identity |

### The cookie prefix, and the underscore

vBulletin builds each cookie name by concatenating the configured prefix onto a
bare base name (`userid`, `password`, `sessionhash`, …) with **no separator**.
The stock prefix is `bb`, so the names on the wire are `bbuserid`,
`bbpassword`, `bbsessionhash` — *no underscore*. This is what vB3.8-era and
vB5 Connect installs actually send, and what LiteSpeed's own vBulletin
guest-cache recipe matches (`RewriteCond %{HTTP_COOKIE} !bbuserid=`). The
`bb_userid` spelling seen on many vB4 boards comes from the prefix itself being
set to `bb_`, not from a different naming scheme — either way the underscore is
part of the *prefix*, not a fixed separator, so do not assume it is there.

Because the prefix is operator-controlled, the rule matches the **suffix**
`userid`/`password`/`imloggedin`, not a hardcoded `bb_` literal — so it covers
`bbuserid`, `bb_userid` and any other prefix equally. A rare full manual rename
of the base cookie name itself (not just the prefix) still evades it — same
caveat class as any other admin-configurable name in this registry.

## Vhost

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    server {
        listen 443 ssl http2;
        server_name forum.example.com;
        root /var/www/vbulletin;
        index index.php;

        location / {
            try_files $uri $uri/ /index.php?$args;
        }

        location ~ \.php$ {
            cache_turbo               ct;
            cache_turbo_backend       vbulletin;

            # No cache_turbo_key: the `vbulletin` preset already folds the
            # language cookie into the key with length-prefixed framing. Do NOT
            # hand-write one that splices $cookie_* values together — unframed
            # concatenation lets a visitor choose a cookie value that reproduces
            # another page's key.
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
curl -sI https://forum.example.com/showthread.php?t=1 | grep -i x-cache-turbo
curl -sI https://forum.example.com/showthread.php?t=1 | grep -i x-cache-turbo  # HIT

# a GUEST carrying only bbsessionhash must still be a HIT.
# (use bb_sessionhash instead if your install's prefix is "bb_")
curl -sI -H 'Cookie: bbsessionhash=abc123' \
     https://forum.example.com/showthread.php?t=1 | grep -i x-cache-turbo     # HIT

# THE ONE THAT MATTERS: a logged-in member must be BYPASS.
curl -sI -H 'Cookie: bbuserid=42; bbpassword=somehash' \
     https://forum.example.com/showthread.php?t=1 | grep -i x-cache-turbo     # BYPASS

# UCP / PM / admin: BYPASS
curl -sI https://forum.example.com/usercp.php | grep -i x-cache-turbo
```

## Gotchas

- **Closed-source, community-corroborated.** No source read is possible;
  confirmed against forum threads and a production LiteSpeed caching config,
  not vBulletin's own code.
- **A full manual cookie rename (not just the `bb` prefix)** evades the
  suffix match. Rare, but possible.
- **`bbsessionhash` is not an auth cookie** — guests have it too. Bypassing
  on it is the classic mistake and would zero the hit rate.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached, regardless of preset.

## PHP settings / gotchas

vBulletin-specific things that bite around a full-page cache:

- **The cookie prefix is configurable, in `config.php` — not the AdminCP.**
  Default is `bb` (cookies land as `bbuserid`, `bbpassword`, …; the prefix is
  concatenated with no separator). It is set per-install as
  `$config['Misc']['cookieprefix']` in **`config.php`**. The AdminCP page
  *Settings > Options > Cookies and HTTP Header Options* is a different thing —
  it controls cookie **path, domain and session timeout**, not the prefix, so
  don't go looking for it there. The preset matches on the `userid`/`password`
  **suffix** rather than a hardcoded `bb_`, so a changed prefix still works —
  but a full manual rename of the base cookie name would need the key/bypass
  rules updated to match.
- **`bbuserid` + `bbpassword` are the member signal.** Their presence means a
  logged-in user and must bypass; a guest carries only `bblastactivity`,
  `bblastvisit`, `bbsessionhash`. Never bypass on `bbsessionhash` — guests
  have it too, and doing so zeroes the hit rate.
- **`/admincp` and `/modcp` must never be cached.** These are logged-in-only
  admin/moderator surfaces (the admin session rides a separate `bbcpsessionhash`
  cookie — again prefix + base name, so `bb_cpsessionhash` on a `bb_`-prefixed
  install); in vB5 the `modcp` directory name is fixed and cannot be renamed. Same
  for login/register and the private-message / UCP flows — all member-state pages.
- **vBulletin's datastore is not the nginx layer.** vB caches its own settings,
  permissions, usergroups, and phrases in an internal *datastore* (DB rows or
  memcached). That is unrelated to the nginx full-page cache and does **not**
  invalidate it — a datastore rebuild after a settings change won't purge stale
  guest pages, so keep `cache_turbo_valid` short or purge via `/_cache` on
  content updates.
- **vB5 Connect is heavy**, so guest full-page caching at nginx is high value —
  it is exactly the uncached guest `showthread.php`/`forumdisplay.php` renders
  (many DB queries + template assembly each) that the cache removes from PHP-FPM.
- **opcache** — enable it; vB5 has a large PHP surface and opcache is a big win
  on the requests that still reach PHP (members, POSTs).
- **`memory_limit`** — vB5 is memory-hungry; 256M is a sane floor, and the
  AdminCP / upgrade scripts want more (upgrade guidance runs to 512M+).
- **`max_execution_time`** — vBulletin's scheduled-task (cron) runner is
  triggered off page loads; keep it high enough (e.g. 300s) that a heavy
  scheduled task doesn't time out. Those requests carry member cookies and
  bypass the cache anyway.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/invision.md`](invision.md) — the other closed-source commercial forum
- [`docs/README.md`](README.md) — all presets
