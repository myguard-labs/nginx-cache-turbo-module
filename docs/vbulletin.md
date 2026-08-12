# vBulletin + cache-turbo

_Last researched: 2026-07-26_

Caching a vBulletin board — current
[vBulletin 6](https://www.vbulletin.com/en/vbulletin-6.html), vBulletin 5
Connect, and the vB4/vB3 legacy line. Vendor documentation identifies `userid`,
`password`, and `sessionhash` as
[logged-in user cookies](https://forum.vbulletin.com/articles/support-documents/reference/4463793-vbulletin-cookies),
but vBulletin is
closed-source and its current download is member-only. Before enabling caching
on vBulletin 6, run the anonymous and authenticated checks below and confirm the
same cookies are present. See the
[prefix note](#the-cookie-prefix-and-the-underscore) — the underscore in `bb_`
is not universal. Closed-source commercial PHP means this cannot receive the same
source-level verification as the open-source presets.

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
community documents them as set **on login and removed on logout**; guest
session-cookie behaviour varies by product line and configuration.
Presence/non-empty-value alone is sufficient; no value-split trick needed.
(`bbimloggedin=yes` also appears in some LiteSpeed/nginx guest-cache configs as
an extra login flag. A
[vBulletin staff response](https://forum.vbulletin.com/forum/vbulletin-5-connect/support-issues-questions/4027789-question-about-remember-me-cookies-and-having-to-log-in-over-and-over)
identifies it as specific to vbulletin.com's own Varnish setup, not a stock
product cookie — treat it as a
harmless extra match, not the primary signal.)

| Cookie | Treatment | Why |
|---|---|---|
| `bbuserid` / `bbpassword` (suffix `userid`/`password`) | **bypass** (non-empty) | set only on login, removed on logout |
| `bbimloggedin` == `yes` | **bypass** | site-specific extra flag used by vbulletin.com's cache; not a stock cookie |
| `bbsessionhash` | **ignore** | session tracking for every visitor including guests |
| `bb_language` (exact name) | **cache key** | presentation, not identity |
| `bblastvisit` / `bblastactivity` | **ignore** | presentation, but per-visit timestamps: keying on them would give every visitor a private entry their own next request invalidates, and let anyone mint unlimited keys to force eviction |

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
            # Preserve the original URL after try_files redirects to index.php.
            cache_turbo_key           $host$request_uri;

            # Keep cookie values out of the base key above: the `vbulletin`
            # preset folds the exact `bb_language` cookie into it with
            # length-prefixed framing. Do NOT hand-write a replacement that
            # splices $cookie_* values together — unframed
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
curl -s -o /dev/null -D- https://forum.example.com/showthread.php?t=1 \
    | grep -i x-cache-turbo
curl -s -o /dev/null -D- https://forum.example.com/showthread.php?t=1 \
    | grep -i x-cache-turbo  # HIT

# a GUEST carrying only bbsessionhash must still be a HIT.
# (use bb_sessionhash instead if your install's prefix is "bb_")
curl -s -o /dev/null -D- -H 'Cookie: bbsessionhash=abc123' \
     https://forum.example.com/showthread.php?t=1 | grep -i x-cache-turbo     # HIT

# THE ONE THAT MATTERS: a logged-in member must be BYPASS.
curl -s -o /dev/null -D- -H 'Cookie: bbuserid=42; bbpassword=somehash' \
     https://forum.example.com/showthread.php?t=1 | grep -i x-cache-turbo     # BYPASS

# UCP / PM / admin: BYPASS
curl -s -o /dev/null -D- https://forum.example.com/usercp.php \
    | grep -i x-cache-turbo
```

## Origin failure: stale-if-error

By default this module serves a stale cached copy when the origin returns 5xx; nginx turns a refused connection into a 502 and a hung one into a 504, so a dead origin is covered. Once the cached copy's TTL has expired there is no grace window unless one is configured — `cache_turbo_keep_stale <time>` supplies it, and it defaults to `24h`. Most CMS/app stacks emit no `stale-if-error` of their own. `cache_turbo_use_stale` selects which statuses count as "down" (default: every 5xx); naming tokens replaces the default rather than extending it. Nothing was ever cached for a URL ⇒ nothing to serve; `error_page 502 503 504 /maintenance.html` is the nicer failure.

```nginx
cache_turbo_keep_stale    2h;
cache_turbo_valid         60s;
```

The copy stays fresh for `60s`; if the origin starts failing after that, the expired copy keeps being served for up to `2h` (`cache_turbo_keep_stale`). Past that window, or with nothing cached at all, `error_page` is the fallback. See the README sections on [which failures count as "the origin is down"](../README.md#which-failures-count-as-the-origin-is-down) and [what outage handling cannot do](../README.md#what-outage-handling-cannot-do).

## Gotchas

> **Subdirectory installs.** This preset's URI rules are root-relative literals
> matched from byte 0 of `r->uri`, so an install mounted under a subdirectory
> (`/shop/`, `/forum/`, …) matches **none** of them — the admin surface
> included. Declare the mount with `cache_turbo_backend_prefix /forum/;` and the
> preset URI tier is compared against the rebased path. Scoping the nginx
> `location` does **not** substitute: it routes requests, it does not rewrite
> `r->uri`. See [frameworks.md](frameworks.md).

- **Closed-source, community-corroborated.** No source read is possible;
  confirmed against forum threads and a production LiteSpeed caching config,
  not vBulletin's own code.
- **A full manual cookie rename (not just the `bb` prefix)** evades the
  suffix match. Rare, but possible.
- **The presentation-key cookie is exactly `bb_language`.** Unlike the auth
  predicates, this key-cookie name does not follow the configured prefix. If
  your board emits a differently named language/style cookie, add that exact
  name with `cache_turbo_key_cookie` or disable the selector; otherwise two
  presentation variants can share an entry.
- **`bbsessionhash` is not a reliable auth cookie** — guest sessions on older
  lines and some configurations carry it too. Bypassing on it is a safe failure
  direction, but can zero the hit rate; verify it with the anonymous check.
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
  install). The preset has an `/admincp/` URI row but no `/modcp/` row; the
  ordinary member cookies should still bypass a logged-in moderator, but add a
  `$request_uri`-based bypass/no-store map for the actual CP paths as a separate
  route guard. The front-controller warning in [docs/README.md](README.md#two-traps-these-guides-keep-pointing-at)
  explains why a PHP-location `cache_turbo_bypass_uri /modcp;` may see only
  `/index.php`. Apply the same treatment to login/register and private-message /
  UCP flows if your current vBulletin release routes them through clean URLs.
- **vBulletin's datastore is not the nginx layer.** vB caches its own settings,
  permissions, usergroups, and phrases in an internal *datastore* (DB rows or
  memcached). That is unrelated to the nginx full-page cache and does **not**
  invalidate it — a datastore rebuild after a settings change won't purge stale
  guest pages, so keep `cache_turbo_valid` short or purge via `/_cache` on
  content updates.
- **Modern vBulletin is heavy**, so guest full-page caching at nginx is high
  value — it is exactly the uncached guest `showthread.php`/`forumdisplay.php` renders
  (many DB queries + template assembly each) that the cache removes from PHP-FPM.
- **opcache** — enable it; vBulletin has a large PHP surface and opcache is a
  big win on the requests that still reach PHP (members, POSTs).
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
