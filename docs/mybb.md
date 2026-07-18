# MyBB + cache-turbo

_Last researched: 2026-07-18_

Caching a MyBB board (verified against MyBB 1.8.40). Clean case: the login
cookie is only ever written on login success, no value predicate needed.

- [The short version](#the-short-version)
- [Why presence alone is safe here](#why-presence-alone-is-safe-here)
- [Vhost](#vhost)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)
- [PHP settings / gotchas](#php-settings--gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend mybb;
```

## Why presence alone is safe here

MyBB's login cookie is named literally **`mybbuser`** — there is no `mybb_`
prefix baked into the base name. MyBB's optional **`cookieprefix`** board
setting (Admin CP → Configuration → Cookies and HTTP) is prepended to *every*
cookie MyBB sets and **defaults to empty** (`inc/functions.php` `my_setcookie()`
does `"{$settings['cookieprefix']}{$name}"`; install default is blank), so on a
stock board the wire name is exactly `mybbuser`. Its value is `uid_loginkey`
and it is written **only** inside the login success path
(`inc/datahandlers/login.php:318`, reached from `member.php`'s `do_login` and
the "remember me" path in `usercp.php`) — a guest structurally cannot receive
it, and MyBB's own guest test is exactly `empty($mybb->cookies['mybbuser'])`
(`inc/class_session.php:88`). Presence alone is therefore sufficient, no value
predicate needed. Because `cookieprefix` is admin-configurable, the preset keys
on the cookie-name **substring** `user` (non-empty) rather than a hardcoded
literal — the same prefix-agnostic technique this module's `phpbb` preset uses
for `_u`.

| Cookie (stock wire name) | Treatment | Why |
|---|---|---|
| `mybbuser` (matched as substring `user`) | **bypass** (presence) | value `uid_loginkey`, written only on login success (`login.php`, `member.php`, `usercp.php`) |
| `sid` | **ignore** | session id issued to every visitor including guests and bots (`inc/class_session.php:123`) — note the base name is `sid`, **not** `mybbsid` |
| `mybb[lastvisit]` / `[lastactive]` / `[threadread]` / `[threadsread]` / `[forumread]` / `[readallforums]` / `[announcements]` / `[referrer]` | **ignore** | guest read-tracking array, not auth (`inc/class_session.php`, `inc/functions_indicators.php`) |
| `mybbtheme` / `mybblang` | **cache key** (manual) | presentation only; set for **guests** in `global.php` when they pick a theme/language |

(With a non-empty `cookieprefix`, prepend it to each of the names above.)

## Vhost

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    server {
        listen 443 ssl http2;
        server_name forum.example.com;
        root /var/www/mybb;
        index index.php;

        location / {
            try_files $uri $uri/ /index.php?$args;
        }

        location ~ \.php$ {
            cache_turbo               ct;
            cache_turbo_backend       mybb;

            # theme/lang are presentation variants, not identity — key on them.
            cache_turbo_key           $host$uri$cookie_mybbtheme$cookie_mybblang$cache_turbo_normalized_args;

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
curl -sI https://forum.example.com/showthread.php?tid=1 | grep -i x-cache-turbo
curl -sI https://forum.example.com/showthread.php?tid=1 | grep -i x-cache-turbo  # HIT

# a GUEST carrying the full cookie set (sid + read-tracking) must still be a
# HIT. If this says BYPASS, something is over-matching the sid cookie.
curl -sI -H 'Cookie: sid=abc123; mybb[lastvisit]=1700000000' \
     https://forum.example.com/showthread.php?tid=1 | grep -i x-cache-turbo     # HIT

# THE ONE THAT MATTERS: a logged-in member must be BYPASS.
curl -sI -H 'Cookie: mybbuser=42_somehash' \
     https://forum.example.com/showthread.php?tid=1 | grep -i x-cache-turbo     # BYPASS

# UCP / PM / posting: BYPASS
curl -sI https://forum.example.com/usercp.php | grep -i x-cache-turbo
```

## Gotchas

- **Setting a `cookieprefix` is safe for this preset** — the substring `user`
  is matched regardless of any prefix MyBB prepends. It is **not** safe for a
  hand-written `map` that hardcodes `mybbuser`; there is no default `mybb_`
  prefix, so don't assume one.
- **`sid` is not an auth cookie.** Guests have it too (base name `sid`, not
  `mybbsid`). Bypassing on it is the classic mistake and costs you the entire
  cache — the preset deliberately does not match it.
- **The `user` substring match also catches `coppauser`** (set transiently to
  `1`/`0` during COPPA registration, `member.php`). This only causes a harmless
  extra bypass for a guest mid-registration — that flow lives under the already
  never-cached `/member.php` surface, so there is no correctness or cache-hit
  impact in practice.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached, regardless of preset.

## PHP settings / gotchas

MyBB-specific notes that interact with the nginx cache layer:

- **`mybbuser` is the one load-bearing signal.** Presence of this cookie (base
  name fixed in code, value `uid_loginkey`) is the whole guest/member split —
  MyBB itself keys logged-in state off `empty($mybb->cookies['mybbuser'])`. Never
  bypass on `sid`; that is issued to everyone.
- **The `mybb[...]` cookie array + `sid` are noise, not identity.** `sid` is the
  visitor session, `mybb[lastvisit]`, `[lastactive]`, `[forumread]`,
  `[threadread]`, `[readallforums]`, `[announcements]`, `[referrer]` are guest
  read-tracking. They must never move the cache key or trigger a bypass.
- **ACP (`/admin/`) must never be cached.** The Admin CP authenticates with its
  own `adminsid` cookie (`SameSite=strict`, `admin/index.php`), separate from the
  front-end login. The preset already lists `/admin/` as a bypass URI, but the
  ACP directory is renameable via `$config['admin_dir']` in `inc/config.php`
  (default `admin`) — if you renamed it, add a matching `cache_turbo off;`/bypass
  for the new path yourself.
- **Cookie name is fixed; domain/path/prefix are not.** `mybbuser`/`sid`/
  `mybb[...]`/`mybbtheme`/`mybblang` base names are hardcoded, but three board
  settings reshape the wire cookies: `cookieprefix` (prepended to all, default
  empty), `cookiedomain` and `cookiepath` (Admin CP → Configuration → Cookies and
  HTTP). A board that sets a prefix shifts every name — re-derive the key/bypass
  accordingly.
- **MyBB's datacache is a different layer.** `$config['cache_store']` in
  `inc/config.php` (default `db`; also `files`, `memcache`, `memcached`, `apc`,
  `xcache`, `redis`) is MyBB's *internal* datacache for board settings, forums,
  usergroups, etc. With `files` it lives under the `cache/` directory
  (`diskCacheHandler`). It is unrelated to and does not replace the nginx
  full-page cache — the two operate independently; do not expect one to invalidate
  the other.
- **opcache.** Enable `opcache.enable=1` with a realistic
  `opcache.memory_consumption` (128–256 MB) and `opcache.max_accelerated_files`
  ≥ 16000 — MyBB plus plugins is a large file set. In production set
  `opcache.validate_timestamps=0` and flush opcache on deploy/upgrade, since the
  ACP writes compiled templates/settings to PHP files (`inc/settings.php`,
  cached templates) that opcache would otherwise serve stale.
- **`memory_limit`.** 128 MB is the practical floor for the front controller;
  large boards, big plugin sets, and ACP operations (backup, theme import)
  benefit from 256 MB.
- **`max_execution_time` for the task runner.** MyBB's scheduled tasks run
  through `task.php` (web-cron or a real cron hitting the URL / CLI). Long jobs —
  pruning, backups, mailouts — can exceed the default 30 s; give the PHP-FPM pool
  (or CLI) that serves `task.php` a longer `max_execution_time`. `task.php` is a
  never-cache surface; keep it out of the cache like `/admin/`.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/phpbb.md`](phpbb.md) — same suffix-match technique, but phpBB needed
  a value predicate where MyBB doesn't
- [`docs/README.md`](README.md) — all presets
