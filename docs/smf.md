# SMF (Simple Machines Forum) + cache-turbo

_Last researched: 2026-07-18_

Caching an SMF board (verified against SMF 2.1.7). SMF's login cookie has an
admin-configurable name and a structured JSON value, so this preset keys on
cookie **presence** rather than a decoded value predicate — safe by
construction, at a small, bounded hit-rate cost (see below).

- [The short version](#the-short-version)
- [Why presence-only, and why it costs hit rate](#why-presence-only-and-why-it-costs-hit-rate)
- [Vhost](#vhost)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)
- [PHP settings / gotchas](#php-settings--gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend smf;
```

## Why presence-only, and why it costs hit rate

SMF's login cookie is named by `$cookiename` in `Settings.php`. That name is
not a fixed literal: `other/install.php` derives it as
`'SMFCookie' . abs(crc32(db_name . db_prefix) % 1000)` — the string `SMFCookie`
followed by a number `0`–`999` fixed at install time (the shipped template
default is `SMFCookie11`). The trailing number is **not** a version suffix; it
is a per-install hash of the database name/prefix, and an admin can rename the
cookie outright. So the rule matches the **substring** `SMFCookie` anywhere in
the `Cookie` header, not one fixed cookie name. That search is raw and
undelimited across names *and* values, so a cookie whose *value* contained
`SMFCookie` would bypass too — the literal is distinctive enough that this is
not a practical concern.

Unlike phpBB — which hands `_u`/`_sid` to every visitor — SMF does **not** set
this cookie for ordinary guests browsing the board. `setLoginCookie()` (in
`Sources/Subs-Auth.php` on 2.1; in SMF 3.0 it is `SMF\Cookie::setLoginCookie()`
in `Sources/Cookie.php`, with `Subs-Auth.php` reduced to a backward-compat
shim) writes it for authenticated members, and *also* with a
guest-empty value for a **cookieless** visitor who lands on the login /
kick-guest / maintenance screens (the `if (empty($_COOKIE))` guard in
`LogInOut.php` / `Subs-Auth.php`). A plain guest reading topics carries only
`PHPSESSID` (SMF uses PHP's default session name), never the login cookie —
which is why keying on `SMFCookie` presence, not `PHPSESSID`, is what keeps the
cache useful.

SMF's own `loadUserSettings()` (in `Sources/Load.php` on 2.1; that file is gone
in SMF 3.0, where the logic lives in the `SMF\` namespace classes) only treats
the cookie as authenticated when the embedded password element is non-empty
(`$id_member = !empty($id_member) && strlen($password) > 0 ? (int) $id_member : 0`);
a guest's value carries `id_member=0` and an empty password field. That is a
real value split, in principle — but in SMF 2.1 the value is a JSON **object**
(`json_encode(array(id, hash, span, domain, path), JSON_FORCE_OBJECT)` →
`{"0":id,"1":"hash",…}`), with a legacy PHP-serialized array (`a:4:{…}`) still
accepted for 2.0→2.1 upgrades. This module's cookie-value engine compares the
**raw wire bytes** against a fixed literal or tests non-emptiness — it does not
decode JSON/serialized structures. There is no safe way to express "decode this
and check field 1" without adding a bespoke parser this preset does not have.

So the preset bypasses on **presence** of the `SMFCookie` substring at all —
correct, but not maximally fast, the same trade XenForo's `xf_session` makes.
Because ordinary guests never receive the cookie, the hit-rate cost is small and
bounded: it lands only on a guest who hit the login / kick-guest / maintenance
screen while cookieless, or who tripped 2FA. The 2FA companion cookie
`<cookiename>_tfa` (written by `setTFACookie()` as `$cookiename . '_tfa'`) is
folded into the same rule.

**SMF 3.0 note.** The file layout above is 2.1's. SMF 3.0 (now the repo's
default branch) moved the cookie code into the `SMF\Cookie` class in
`Sources/Cookie.php`; `Sources/Load.php` no longer exists and
`Sources/Subs-Auth.php` is a backward-compat shim. The cookie **names** and the
JSON value format are unchanged from 2.1, so **no rule change is needed** — only
the source citations differ.

**Do not "optimise" this into a hand-decoded value check** without actually
parsing the array — a string-prefix guess against the guest-canonical value is
not a safe substitute, and shipping one un-decoded risks misclassifying a real
member's cookie as guest-shaped.

## Vhost

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    server {
        listen 443 ssl http2;
        server_name forum.example.com;
        root /var/www/smf;
        index index.php;

        location / {
            try_files $uri $uri/ /index.php?$args;
        }

        location ~ \.php$ {
            cache_turbo               ct;
            cache_turbo_backend       smf;

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
curl -sI https://forum.example.com/index.php?topic=1.0 | grep -i x-cache-turbo
curl -sI https://forum.example.com/index.php?topic=1.0 | grep -i x-cache-turbo  # HIT

# a GUEST who hit the login page while cookieless (SMFCookie, empty password)
# will now BYPASS — this is the expected, bounded hit-rate cost, not a bug.
# (Value shape {"0":0,"1":"",...} is illustrative; the preset keys on presence,
#  not the bytes. Use the site's real cookie name if it isn't SMFCookie11.)
curl -sI -H 'Cookie: SMFCookie11=%7B%220%22%3A0%2C%221%22%3A%22%22%2C%222%22%3A0%7D' \
     https://forum.example.com/index.php?topic=1.0 | grep -i x-cache-turbo    # BYPASS

# THE ONE THAT MATTERS: a logged-in member must be BYPASS.
curl -sI -H 'Cookie: SMFCookie11=%7B%220%22%3A42%2C%221%22%3A%22somehash%22%2C%222%22%3A0%7D' \
     https://forum.example.com/index.php?topic=1.0 | grep -i x-cache-turbo    # BYPASS
```

## Gotchas

- **Presence-only, not the value predicate the guest/member split would ideally
  use.** See above — this is a deliberate, documented compromise, not an
  oversight.
- **Cookie name is per-install, not a version suffix.** `install.php` derives it
  as `SMFCookie` + `abs(crc32(db_name . db_prefix) % 1000)` (`0`–`999`; template
  default `SMFCookie11`), and an admin can rename it. The substring match handles
  every stock name; if the admin renamed it away from the `SMFCookie` prefix the
  presence rule stops firing — see PHP settings below.
- **SMF sends no reliable `Cache-Control: private`** — unlike Drupal or
  MediaWiki, there is no origin-side second line of defence here.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached, regardless of preset.

## PHP settings / gotchas

SMF-specific knobs that interact with this preset:

- **Cookie name is admin-configurable (`$cookiename`).** The preset keys on the
  `SMFCookie` substring, which covers every stock install (`SMFCookie11`,
  `SMFCookie<0–999>`). If the admin renamed the cookie in `Settings.php` to
  something without that prefix, the presence rule no longer fires and logged-in
  members can be served cached guest pages. Confirm with
  `grep cookiename /path/to/forum/Settings.php` before trusting the preset, and
  key the rule on the actual name if it was changed.
- **SMF has its own cache, independent of this layer.** `$cache_enable` in
  `Settings.php` runs `0` (off) through `3` (aggressive); `$cache_accelerator`
  selects the backend (`''`/`smf` = file cache under `$cachedir`, default
  `cache/`; or `apcu`, `memcached`/`memcache` via `$cache_memcached`, etc.). That
  cache stores rendered fragments and per-member query results; the cache-turbo
  layer stores whole guest responses. They stack — leave `$cache_enable` on (2+
  with APCu or memcached on a busy board) so member and dynamic requests, which
  always bypass cache-turbo, stay fast. The on-disk `cache/` dir must be
  writable by PHP-FPM.
- **`?action=` surfaces must reach PHP.** SMF drives everything off
  `index.php?action=…`; `admin`, `login`/`login2`/`logintfa`, `logout`, `pm`,
  `post`/`post2` are state-changing or per-member and must never be served from
  cache. `SMFCookie` presence covers logged-in members, but a logged-out visitor
  hitting `?action=login` (or `logout`, `post`, `pm`) must not be cached either —
  if you widen guest caching, exclude the mutating actions explicitly.
- **SMF separates query arguments with `;`, not `&`.** A real board URL looks
  like `index.php?topic=12.0;action=post`, and PHP's `arg_separator.input`
  accepts it. The preset's argument scanner splits on both `;` and `&`, checks
  every occurrence of a name (not only the first), and percent-decodes before
  comparing, so `?%61ction=log%69n` and `?u=42;action=login` classify exactly
  like the plain form. If you write your own `cache_turbo_bypass` rules against
  `$arg_action`, note that nginx's own `$arg_` variables do NOT do any of
  this — they split on `&` only and never decode.
- **opcache.** Keep `opcache.enable=1` with a generous
  `opcache.memory_consumption` (128M+) and a high `opcache.max_accelerated_files`
  (SMF ships ~120 `Sources/*.php` plus themes/mods). cache-turbo removes the FPM
  round-trip for guests, but members and every `?action=` still compile SMF.
- **`memory_limit`.** Large boards with many mods want 256M+; the memory-hungry
  paths (package manager, maintenance, large PM/mail queues) are admin actions
  that always bypass the cache.
- **`max_execution_time` for the scheduled-task runner.** SMF runs scheduled
  tasks through `cron.php`, triggered either by an inline-JS AJAX `GET` on page
  loads (traffic-based) or by a real OS cron entry; the runner calls
  `@set_time_limit(300)`, so give the FPM pool headroom (`max_execution_time`
  and `request_terminate_timeout` ≥ 300s) or long mail-queue / task runs get
  killed mid-flight. Note `cron.php` matches `\.php$` and returns a 1×1 GIF
  (`content-type: image/gif`) with **no** `Cache-Control` header, so it is
  technically cacheable — the changing `?ts=` query keeps keys distinct in
  practice, but if you cache by path alone, exclude `cron.php` so scheduled
  tasks keep firing for cached visitors.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/phpbb.md`](phpbb.md) — the same guest-issued-cookie shape, precise
  value predicate possible there because phpBB's value is a bare integer
- [`docs/README.md`](README.md) — all presets
