# Vanilla Forums + cache-turbo

_Last researched: 2026-07-18_

Caching a Vanilla Forums board. Shippable, but **verify empirically on your
install before relying on it** — see the caveat below.

- [The short version](#the-short-version)
- [The identity cookie, and the caveat](#the-identity-cookie-and-the-caveat)
- [Vhost](#vhost)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend vanilla;
```

## The identity cookie, and the caveat

Vanilla's identity cookie (`Gdn_CookieIdentity::SetIdentity()`) is written
**only** at login/SSO time — an HMAC-signed opaque payload keyed off a
site-specific cookie salt. Unlike phpBB/SMF/XenForo, a true guest never
receives *that* cookie, so presence classifies a member with no value
predicate needed. Its name is not fixed: it is `Garden.Cookie.Name`, whose
stock default is `Vanilla` (`conf/config-defaults.php`), so the preset matches
the substring **`Vanilla=`** — the default name plus its delimiter — in the
Cookie header. The trailing `=` is deliberate: it excludes the guest-issued
`Vanilla-tk` and `Vanilla-Vv` siblings that share the base prefix (see below).
A renamed cookie (`Garden.Cookie.Name` changed, or the SaaS `vf_[site]_<hash>`
naming) won't match and needs a hand-written `cache_turbo_bypass`.

**Verification status:** the default name and the login-only identity cookie
are confirmed against Vanilla's own source (`Garden.Cookie.Name = 'Vanilla'` in
`conf/config-defaults.php`; `SetIdentity()`/`GetIdentity()` in
`library/core/class.cookieidentity.php`) and its official KB,
[Cookies Used in Vanilla](https://success.vanillaforums.com/kb/articles/86-cookies-used-in-vanilla).
Current-master could not be line-cited — `github.com/vanilla/vanilla` is now
auth-gated — so the legacy Garden tree plus the KB are the citable sources.
Confirm on your own install before going live:

```bash
curl -sI https://forum.example.com/ | grep -i set-cookie
# a clean first-ever request must show NO "Vanilla=" identity cookie here
```

**The prefix collision the `=` avoids:** the same base name prefixes two
cookies Vanilla issues to *everyone*, guests included — `Vanilla-tk` (the CSRF
transient key) and `Vanilla-Vv` (a ~20-minute sliding visit tracker), both
documented in the KB above. A bare-prefix rule would match those and serve
**BYPASS** to every returning guest, leaving the cache to answer only
cookie-less first hits and crawlers. Matching `Vanilla=` instead anchors on the
identity cookie's delimiter, so `Vanilla-tk` and `Vanilla-Vv` fall through and
ordinary anonymous traffic still gets cached. If you rename
`Garden.Cookie.Name`, the same reasoning applies to your prefix: match
`<name>=`, not `<name>`.

If your install (or a plugin/SSO integration) sets the identity cookie
`Vanilla=` for anonymous visitors too, this preset is unsafe for you — fall
back to `cache_turbo off` or a hand-verified `cache_turbo_bypass` until that's
fixed upstream or in your install.

## Vhost

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    server {
        listen 443 ssl http2;
        server_name forum.example.com;
        root /var/www/vanilla;
        index index.php;

        location / {
            try_files $uri $uri/ /index.php?$args;
        }

        location ~ \.php$ {
            cache_turbo               ct;
            cache_turbo_backend       vanilla;

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
# guest discussion: MISS then HIT
curl -sI https://forum.example.com/discussion/1/hello | grep -i x-cache-turbo
curl -sI https://forum.example.com/discussion/1/hello | grep -i x-cache-turbo  # HIT

# THE ONE THAT MATTERS: a logged-in member must be BYPASS.
curl -sI -H 'Cookie: Vanilla=abc.signed.payload' \
     https://forum.example.com/discussion/1/hello | grep -i x-cache-turbo     # BYPASS

# a returning GUEST carrying only -tk / -Vv must still be cacheable:
# the rule matches "Vanilla=", which neither of those contains.
curl -sI -H 'Cookie: Vanilla-Vv=1; Vanilla-tk=2' \
     https://forum.example.com/discussion/1/hello | grep -i x-cache-turbo     # HIT

# dashboard / entry (login/register/SSO): BYPASS
curl -sI https://forum.example.com/dashboard/ | grep -i x-cache-turbo
```

## Gotchas

- **Verified against the KB + legacy Garden source, not current master** —
  `github.com/vanilla/vanilla` is auth-gated, so confirm with a live anonymous
  `curl` before trusting this in production (see caveat above).
- **The `-tk` / `-Vv` guest cookies share the `Vanilla` prefix** — the preset
  matches `Vanilla=` rather than `Vanilla` so those two do not trip it and
  returning guests stay cacheable. Keep that `=` in mind if you write your own
  `cache_turbo_bypass` for a renamed cookie.
- **Query-string routing (`?p=/entry/signin`) dodges the URI bypasses.** The
  `/dashboard` and `/entry/` bypass rules match the request *path*; with
  `Garden.RewriteUrls` off the route lives in the `p=` query arg and `r->uri` is
  just `/index.php`, so those surfaces won't be recognised. Enable pretty URLs
  (as in the vhost above) or add your own `cache_turbo_bypass`.
- **A guest-issued identity `Vanilla=` cookie on your install breaks this preset
  silently** — no known stock trigger writes it for a guest, but a plugin or
  SSO integration could.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached, regardless of preset.

## PHP settings / gotchas

Vanilla-specific PHP-FPM notes for the box behind this cache:

- **`Garden.Cookie.Name` drives the whole cookie family.** The identity cookie,
  the `-tk` CSRF token and the `-Vv` visit tracker all take this prefix (default
  `Vanilla`). If an operator sets it in `conf/config.php`
  (`$Configuration['Garden']['Cookie']['Name']`), the preset's `Vanilla=`
  substring stops matching — retune with `cache_turbo_bypass`, keyed on
  `<your-name>=` so the `-tk` / `-Vv` siblings stay out of it. The SaaS naming
  `vf_[site]_<hash>` is a different prefix and never matches; this preset targets
  the self-hosted open-source build.
- **`Gdn_Cache` is a *separate* layer.** Vanilla has its own object cache
  (`Cache.Method` — default `dirtycache`, optionally `memcached` or `apc`) that
  memoises config, sessions and permissions inside PHP. It caches nothing at the
  HTTP layer, so it neither helps nor conflicts with cache-turbo — the two stack.
  Leave memcached/APCu enabled for logged-in (BYPASS) traffic; it is what keeps
  the un-cached member path fast.
- **Never let `/dashboard` or `entry/*` be cached at the app layer either.** The
  preset already BYPASSes them at the edge; make sure no Vanilla plugin
  full-page-caches admin or auth routes underneath.
- **OPcache on**, with a comfortable `opcache.memory_consumption` (Vanilla is a
  large PHP tree) and `opcache.validate_timestamps=0` in production (bump the
  revalidation manually on deploy).
- **`memory_limit` ≥ 256M.** Dashboard rebuilds, addon/utility structure runs and
  large imports (Porter) are memory-hungry; the default 128M can OOM them.
- **`max_execution_time` for the utility/cron runner.** `/utility/update`,
  `utility/structure` and the analytics/queue cron can run for minutes; give the
  CLI/cron FPM pool (or `php` CLI) a high or unlimited `max_execution_time` so a
  schema update doesn't die mid-run. Front-end pool can stay short.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/README.md`](README.md) — all presets
