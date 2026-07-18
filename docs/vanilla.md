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
Cookie header. The trailing `=` is deliberate: it excludes the
`Vanilla-tk` (guest-issued) and `Vanilla-Vv` siblings that share the base
prefix (see below).
A renamed cookie (`Garden.Cookie.Name` changed, or the SaaS `vf_[site]_<hash>`
naming) won't match and needs a hand-written `cache_turbo_bypass` **plus a
matching `cache_turbo_no_store`** — the bypass skips only the lookup and still
stores the member's page.

**Verification status — read this before trusting the citations.** There is no
longer a live upstream source to check this against. `github.com/vanilla/vanilla`
now returns **404** (repository page, `raw.githubusercontent.com` and the REST
API alike; the `vanilla` GitHub *org* still exists, but the forum repo is gone),
and the vendor KB article
[Cookies Used in Vanilla](https://success.vanillaforums.com/kb/articles/86-cookies-used-in-vanilla)
no longer renders its body. **A reader cannot follow either citation**, and this
page does *not* rest on a confirmed reading of current Vanilla source.

What it actually rests on: surviving community forks of the **Garden**-era tree
(last pushed ~2013), where `Garden.Cookie.Name` defaults to `'Vanilla'` in
`conf/config-defaults.php` and `SetIdentity()`/`GetIdentity()` live in
`library/core/class.cookieidentity.php`. That is a decade-stale snapshot of a
codebase that has since been rewritten. Treat the cookie shape below as
plausible-but-unverified and **confirm it on your own install** before going
live:

```bash
curl -sI https://forum.example.com/ | grep -i set-cookie
# a clean first-ever request must show NO "Vanilla=" identity cookie here
```

**The prefix collision the `=` avoids:** the same base name prefixes two more
cookies — `Vanilla-tk` (the CSRF transient key), which *is* issued to guests: an
anonymous visitor loading any form-bearing page gets one; and `Vanilla-Vv`, a
~20-minute sliding visit tracker. (`-Vv` is reported in the field only alongside
the logged-in cookie set, which suggests it is member-only rather than
guest-issued; with the upstream repo gone this could not be re-confirmed
against source, so the rule below is written to be correct either way.) A
bare-prefix rule would match `Vanilla-tk` and serve
**BYPASS** to every returning guest, leaving the cache to answer only
cookie-less first hits and crawlers. Matching `Vanilla=` instead anchors on the
identity cookie's delimiter, so `Vanilla-tk` and `Vanilla-Vv` fall through and
ordinary anonymous traffic still gets cached. If you rename
`Garden.Cookie.Name`, the same reasoning applies to your prefix: match
`<name>=`, not `<name>`.

If your install (or a plugin/SSO integration) sets the identity cookie
`Vanilla=` for anonymous visitors too, the failure is a **hit-rate** one, not a
leak: the preset bypasses on the cookie's *presence*, so those guests simply
bypass the cache and are served from the origin. Nothing private is stored, and
no guest response is captured under a shared key. You do not need
`cache_turbo off`. Confirm it with `$cache_turbo_status` (see
[Checking it works](#checking-it-works)) — a board-wide `BYPASS` on
anonymous traffic is the tell — and if it costs you too much, narrow the rule
with a hand-verified `cache_turbo_bypass` on a cookie your guests do not get.

## Known gap: the API (`/api`) has no rule

Vanilla's API v2 is **Bearer-authenticated**, which makes it the same
header-auth class as `magento /rest`, `drupal /jsonapi` and `xenforo /api/` —
all of which *do* ship a URI rule. An API client sends no `Vanilla=` cookie, so
the cookie rule above is structurally blind to it.

**No `/api` row is shipped, deliberately.** `github.com/vanilla/vanilla` now
404s (repo, raw and API alike; the org survives), so there is no upstream tree
left to verify the prefix against, and every surviving reference is a
Garden-era fork last pushed in 2013. Adding a row from recollection is what
produced the dead `/admin.php` and `/message_send.php` rows in the PunBB
preset, so it is not being repeated here.

If you serve the API, add it yourself:

```nginx
cache_turbo_bypass_uri /api;
cache_turbo_no_store;
```

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

- **No live upstream source backs this page.** `github.com/vanilla/vanilla`
  404s and the vendor KB article no longer renders; the only surviving basis is
  the Garden-era tree (last pushed ~2013). Confirm with a live anonymous
  `curl` before trusting this in production (see caveat above).
- **The `-tk` (guest-issued) and `-Vv` cookies share the `Vanilla` prefix** — the preset
  matches `Vanilla=` rather than `Vanilla` so those two do not trip it and
  returning guests stay cacheable. Keep that `=` in mind if you write your own
  `cache_turbo_bypass` (and its `cache_turbo_no_store` partner) for a renamed cookie.
- **Query-string routing (`?p=/entry/signin`) dodges the URI bypasses.** The
  `/dashboard` and `/entry/` bypass rules match the request *path*; with
  `Garden.RewriteUrls` off the route lives in the `p=` query arg and `r->uri` is
  just `/index.php`, so those surfaces won't be recognised. Enable pretty URLs
  (as in the vhost above) or add your own `cache_turbo_bypass` **and**
  `cache_turbo_no_store` (a bypass alone still stores).
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
  substring stops matching — retune with `cache_turbo_bypass` **and
  `cache_turbo_no_store`**, keyed on
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
