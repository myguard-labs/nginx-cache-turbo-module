# Invision Community + cache-turbo

_Last researched: 2026-07-18_

Caching an Invision Community (IPS4) board. Closed-source, so this preset rests
on IPS's own developer docs rather than a source read — but those docs are
unusually explicit: they name a cookie *for this exact purpose*.

- [The short version](#the-short-version)
- [The cookie IPS built for this](#the-cookie-ips-built-for-this)
- [Vhost](#vhost)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)
- [PHP settings / gotchas](#php-settings--gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend invision;
```

## The cookie IPS built for this

IPS's own developer docs describe `ips4_loggedIn` as existing **for caching
systems to check** — "set after login, used by caching mechanisms to identify
if you are logged in." That is a stronger, purpose-built signal than most
forums in this registry ship; most require reverse-engineering a remember-me
cookie IPS never intended for the job.

| Cookie | Treatment | Why |
|---|---|---|
| `ips4_loggedIn` (suffix `_loggedIn`) | **bypass** (presence) | vendor-documented login signal |
| `ips4_member_id` / `ips4_login_key` / `ips4_device_key` / `ips4_pass_hash` | **ignore** | remember-me / device-trust tokens (set on login with "Remember Me") — a returning visitor can carry them *before* IPS re-establishes the session and re-sets `_loggedIn`, so they are not a reliable "is a member right now" signal on their own |
| `ips4_IPSSessionFront` | **ignore** | issued to every visitor, guests included — the xf_session/_forum_session shape |
| `ips4_hasJS` / `ips4_theme` / `ips4_language` | **cache key** (manual) | cosmetic, shared by everyone who picked the same value |

The `ips4_` prefix is admin-configurable (Overriding Default Cookie Options), so
the rule matches the **suffix** `_loggedIn`, not the literal `ips4_loggedIn` —
the same prefix-agnostic technique this module's `phpbb` and `drupal` presets
use.

IPS routes clean URLs to `app=core&module=...&do=...` controller dispatch
rather than one stable posting path, so posting/messaging/moderation surfaces
are matched as `do=` query args:

```nginx
cache_turbo         ct;
cache_turbo_backend invision;
```

bypasses `/admin`, `/login`, `/register`, `/lostpassword`, `/messenger`, and any
request whose query string contains `do=compose`, `do=post`, `do=reply`,
`do=report`, or `module=messaging`.

## Vhost

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    server {
        listen 443 ssl http2;
        server_name forum.example.com;
        root /var/www/invision;
        index index.php;

        location / {
            try_files $uri $uri/ /index.php?$args;
        }

        location ~ \.php$ {
            cache_turbo               ct;
            cache_turbo_backend       invision;

            cache_turbo_valid         60s;
            cache_turbo_valid         404 410 1m;
            cache_turbo_preset        balanced;
            cache_turbo_cache_control honor;

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
curl -sI https://forum.example.com/topic/1-hello/ | grep -i x-cache-turbo
curl -sI https://forum.example.com/topic/1-hello/ | grep -i x-cache-turbo   # HIT

# THE ONE THAT MATTERS: a logged-in member must be BYPASS.
curl -sI -H 'Cookie: ips4_loggedIn=1' \
     https://forum.example.com/topic/1-hello/ | grep -i x-cache-turbo       # BYPASS

# admin: BYPASS
curl -sI https://forum.example.com/admin/ | grep -i x-cache-turbo
```

## Gotchas

- **Vendor-attested, not source-verified.** IPS4 is closed-source; this rests
  on IPS's own official docs, which happen to be unusually explicit about the
  cookie's purpose. Treat it as high-confidence, not code-proven.
- **Custom cookie prefix.** If your board renamed the `ips4_` prefix, the
  suffix match still works — only a rename of the `loggedIn` segment itself
  would break it, which is not exposed as an admin setting.
- **Third-party apps/plugins** may add their own member-only surfaces (a
  marketplace plugin's private area). The preset is a floor, not a boundary
  for those.
- **Renamed ACP folder.** `/admin` is the *default* Admin CP path, but it is
  admin-renameable (the `CP_DIRECTORY` constant in `conf_global.php`). If your
  board hardened the ACP to a non-default folder, add that path to the bypass
  yourself — the preset only knows the stock `/admin`.
- **Remember-me lag is by design.** Because bypass keys on `_loggedIn`, a
  returning visitor who still holds `ips4_member_id`/`ips4_device_key` but whose
  session has lapsed is served the cached guest page until IPS re-authenticates
  and re-sets `_loggedIn` on the next uncached request. This mirrors IPS's own
  guest-page-cache behaviour (a member may briefly see the guest view until a
  refresh) — shorten `cache_turbo_valid` if that window bothers you.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached, regardless of preset.

## PHP settings / gotchas

Invision-specific PHP/runtime notes for a self-hosted board sitting behind this
preset. None of these are nginx settings — they live in `php.ini`/FPM pool config
or the IPS Admin CP.

- **`ips4_loggedIn` is the guest/member signal — nothing lighter exists.** IPS's
  own developer docs describe a `loggedIn()` helper that reads this cookie as a
  *pre-init* check, specifically so the guest-cache layer can decide guest-vs-member
  before the framework (and a DB connection) spins up. The nginx preset keys on the
  same cookie for the same reason. The heavier `ips4_member_id` + `ips4_pass_hash`
  pair (member id, plus a hash that proves the id was not forged) is the durable
  "remember who you are" identity, but it can be present for a lapsed session, so
  it is *not* the right gate — treat `_loggedIn` as authoritative.
- **IPS has its own "Cache Guest Page Output" datastore layer.** Under *Admin CP →
  System → (Advanced Configuration) → Data Storage*, IPS can cache whole guest
  pages into its configured datastore (Redis/Memcache/disk) and serve them without
  a DB hit. That is a *second* full-page cache below the nginx layer. Running both
  is fine, but redundant: pick one as the primary. If nginx is doing full-page
  caching, IPS's guest-page cache mostly just adds a shorter inner TTL — keep IPS's
  guest TTL short (or off) and let nginx be the front cache, or vice-versa. IPS now
  treats its classic guest-page cache as legacy and steers larger sites toward a
  CDN for guest serving (unverified for your exact build — confirm in your ACP).
- **ACP (`/admin`) must never be cached or opcache-poisoned.** The preset bypasses
  `/admin`; also make sure no upstream layer (opcache aside) caches ACP responses.
  Opcache itself is fine and recommended — enable `opcache.enable`, size
  `opcache.memory_consumption` (128–256M) and `opcache.max_accelerated_files`
  (≥ 16k; IPS ships thousands of PHP files) generously.
- **`memory_limit` ≥ 128M, more for big boards.** IPS enforces a 128M floor and
  the ACP throws a warning below it. Communities with large galleries or on-the-fly
  image processing (thumbnails, watermarks via GD/Imagick) want 256M+.
- **The task/cron runner and its `max_execution_time`.** IPS runs background tasks
  either *traffic-triggered* (piggy-backed on page loads — and only on **logged-in
  member** page loads, never guests) or via a real cron once per minute (the
  recommended method). This bites directly with front caching: if nginx serves most
  guest traffic straight from cache, far fewer member requests reach PHP to pump the
  task queue, so a traffic-triggered board can backlog. **Switch IPS to the cron
  method** (*Admin CP → System → Settings → Advanced Configuration → Server
  Environment → Task Method*) when you put a full-page cache in front. The CLI cron
  invocation runs with relaxed limits (`php -d memory_limit=-1 -d
  max_execution_time=0 …`); leave the FPM `max_execution_time` at a normal web value
  (30–60s) — the long-running work belongs to the CLI runner, not the web SAPI.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/xenforo.md`](xenforo.md) — the other big commercial forum suite
- [`docs/README.md`](README.md) — all presets
