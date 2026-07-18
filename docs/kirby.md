# Kirby + cache-turbo

_Last researched: 2026-07-18_

Caching a Kirby (flat-file PHP CMS) site. **The best-shaped traffic of any preset
here** — a flat-file site is almost entirely public pages that are byte-identical
for every logged-out visitor, which is the entire business case for a page cache.

- [The short version](#the-short-version)
- [What the preset matches](#what-the-preset-matches)
- [The one condition — and why it's safe](#the-one-condition--and-why-its-safe)
- [Vhost](#vhost)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend kirby;     # implies cache_turbo_cache_control honor
```

That is genuinely all most Kirby sites need.

## What the preset matches

| Check | Values |
|---|---|
| Cookie header substrings | `kirby_session` |
| URI prefixes | `/panel` |
| Query args | — |

**`kirby_session` is the rare cookie that is both shippable and meaningful.** It is
a **stable literal** (`session.cookieName`) — no per-install hash, no `APP_NAME`
slug, no admin-settable prefix — *and* Kirby creates a session only when something
is actually stored in it, so a plain anonymous GET of a public page is issued **no
cookie at all**.

Stable **and** not-guest-issued is the pair that every rejected candidate failed:

| App | Why it fails |
|---|---|
| **Grav** | `grav-site-<hash>` — guest-issued **and** per-install |
| **Craft** | `CraftSessionId` — stable, but handed to **every** anonymous visitor |
| **October** | `october_session` — stable, but guest-issued |
| **Statamic** | `<APP_NAME>_session` — per-install **and** guest-issued (fails both rules at once) |

**`/panel`** is the admin (`panel.slug`, rarely moved).

**`/media/` is deliberately NOT a preset URI.** Kirby serves assets from
`/media/<hash>/` with no per-request permission view, so it is static content that
*should* cache. Bypassing it would be a self-inflicted wound — and the runtime test
asserts it keeps caching, so nobody "helpfully" adds the prefix later.

## The one condition — and why it's safe

Kirby's **`csrf()` helper creates a session cookie**. From Kirby's own privacy
guide: *"When you use the csrf() helper, Kirby will create a session cookie."*

So a template that renders a contact, search, or comment form issues
`kirby_session` **to guests on that page**, and those pages stop caching.

**That costs hits. It never leaks.** The error direction is *bypass a guest* — a
miss — not *serve a member's page to a stranger*. That asymmetry is the whole
reason this preset ships and [Flarum's does
not](README.md#apps-we-deliberately-do-not-ship-a-preset-for): Flarum's failure
direction is inverted, so a logged-in user who did not tick "remember me" would be
served a **cached anonymous page**. A leak, not a lost hit. Same shape of
conditional, opposite consequence.

Check which of your pages are affected:

```bash
# A page with no form -- must set NO cookie.
curl -sI https://example.com/about | grep -i set-cookie
# (nothing)  <- caches

# A page with a contact form calling csrf() -- will set one.
curl -sI https://example.com/contact | grep -i set-cookie
# Set-Cookie: kirby_session=...   <- this page will not cache. Expected.
```

If a form page's hit rate matters more than its CSRF protection (it usually does
not), move the form to its own URL, or render the token via JS from a separate
uncached endpoint. Most sites should just accept the miss.

## Vhost

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    server {
        listen 443 ssl http2;
        server_name example.com;
        root /var/www/kirby;
        index index.php;

        location / {
            try_files $uri $uri/ /index.php$is_args$args;
        }

        location ~ \.php$ {
            cache_turbo         ct;
            cache_turbo_backend kirby;     # implies cache_control honor

            cache_turbo_valid   60s;
            cache_turbo_valid   404 410 1m;
            cache_turbo_preset  balanced;

            include        fastcgi_params;
            fastcgi_param  SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_pass   unix:/run/php/php-fpm.sock;
        }

        # Kirby's asset pipeline: content-addressed under /media/<hash>/.
        # NOT a preset URI on purpose -- this should cache hard.
        location ^~ /media/ {
            expires 30d;
            access_log off;
        }

        # Kirby's own storage must never be web-readable. This is a Kirby
        # hardening rule, not a caching one -- but it belongs in every vhost.
        # `^~` is load-bearing: regex locations are tested in DECLARATION order,
        # so a plain `~ ^/(content|site|kirby)/` written after `~ \.php$` would
        # never run and /content/... .php would execute in php-fpm.
        location ^~ /content/ { deny all; }
        location ^~ /site/    { deny all; }
        location ^~ /kirby/   { deny all; }

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

> Use **GET**, not `curl -sI`. A `HEAD` response is never stored, so `-I` reports
> `MISS` forever on a perfectly working cache.

```bash
# anonymous page: MISS then HIT
curl -s -D- -o /dev/null https://example.com/about | grep -i x-cache-turbo
curl -s -D- -o /dev/null https://example.com/about | grep -i x-cache-turbo

# panel: BYPASS
curl -s -D- -o /dev/null https://example.com/panel/pages | grep -i x-cache-turbo

# logged-in panel user must never be served from cache
curl -s -D- -o /dev/null -H 'Cookie: kirby_session=abc' https://example.com/about \
    | grep -i x-cache-turbo          # BYPASS

# /media/ is static and must HIT -- it is not a preset URI on purpose
curl -s -D- -o /dev/null https://example.com/media/pages/home/logo.svg \
    | grep -i x-cache-turbo          # HIT
```

## Gotchas

- **A form page will not cache.** Any template calling `csrf()` issues
  `kirby_session` to guests. Expected, and safe — see
  [above](#the-one-condition--and-why-its-safe). Do not "fix" it by removing the
  cookie from the bypass list; that would cache a page for a visitor whose CSRF
  token is in someone else's session.
- **Renaming the cookie breaks the preset.** If you set
  `session.cookieName` to something else, the shipped `kirby_session` substring
  never matches — silently. Add your own `cache_turbo_bypass $cookie_<newname>;`
  **and** `cache_turbo_no_store $cookie_<newname>;` — the bypass only skips the
  lookup, so on its own the authenticated response is still stored.
- **Kirby's own page cache is a different layer.** It lives in PHP and makes the
  origin fast, which is what your cache-turbo *misses* hit. Leave it on; the two
  compose.
- **`/panel` has no trailing slash in the preset, but matches on a path-segment
  boundary.** The prefix matches `/panel`, `/panel/`, and `/panel/pages` — but
  NOT a different segment that merely shares the letters, such as
  `/panels-and-doors` (which caches normally). The rule is: after the prefix the
  URL must end or continue with `/` or `.`. If you relocate the panel via
  `panel.slug`, add a `cache_turbo_bypass` plus a matching `cache_turbo_no_store`
  (the bypass alone still stores) — though `kirby_session` still guards
  every authenticated request, so you lose an optimisation, not a guarantee.
- **Don't set `cache_turbo_cache_control ignore`.** It overrides the `honor` that
  `cache_turbo_backend` implies.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are never
  cached, regardless of preset. Those floors hold — and they are why a page that
  *issues* `kirby_session` is never captured in the first place.

## PHP settings / gotchas

Kirby-specific PHP-side notes. General FPM tuning lives elsewhere; these are the
knobs that behave differently *because* the app is Kirby.

- **Two cache layers, one of which self-invalidates — the other does not.** Kirby's
  own page cache (`cache.pages`, enabled in `site/config/config.php`) writes rendered
  pages to `site/cache/` and is **automatically purged when you edit that page in the
  Panel**. cache-turbo sits in front of it and has no such hook — editing content in
  the Panel does *not* reach into nginx and drop the stored copy. So the two layers
  compose (Kirby's makes the origin fast, which is what a cache-turbo *miss* costs),
  but only the inner one is content-aware. Keep the nginx layer **TTL-bound**
  (`cache_turbo_valid 60s;` in the vhost above) so a Panel edit is visible within one
  TTL, or purge the affected keys via the `cache_turbo_admin` endpoint after publishing.
  Do not set a long `cache_turbo_valid` and assume edits appear immediately — they will
  not. Kirby's inner cache only stores plain `GET`/`HEAD` responses with no query
  string, request data, or session — which is exactly the traffic cache-turbo captures,
  so the two agree on what is cacheable.
- **`kirby_session` is the login-vary signal, and it lives in PHP.** Kirby issues the
  cookie only when a session actually stores something (login, or a `csrf()` call — see
  [above](#the-one-condition--and-why-its-safe)); it is not handed to anonymous GETs.
  That laziness is a Kirby property, not an nginx one — if a plugin or template widens
  when a session is created (form handlers such as Kirby Uniform use `csrf()`, so their
  pages set it), more pages will carry the cookie and correctly stop caching.
- **Keep the Panel out of the cache path.** `/panel` (`panel.slug`) is authenticated
  and already in the preset's bypass list; never add a `cache_turbo` layer that would
  store Panel responses, and if you relocate the Panel via `panel.slug`, mirror it with
  a `cache_turbo_bypass` and a matching `cache_turbo_no_store` — the bypass alone
  skips only the lookup and still stores (the `kirby_session` cookie still guards
  it, so you lose an optimisation, not the guarantee).
- **opcache pays off unusually well here.** Kirby is many small PHP files loaded per
  request (templates, snippets, models, the core), so a warm opcode cache removes a lot
  of per-request compile time on every origin miss. Enable `opcache.enable=1` and give
  `opcache.memory_consumption` and `opcache.max_accelerated_files` room for the whole
  tree — Kirby's file count is higher than a monolithic app of the same size.
- **`memory_limit` and `max_execution_time` are sized by thumbnail generation, not page
  rendering.** Kirby generates image thumbs **on demand** (GD/ImageMagick) on first
  request, then serves the result from `/media/<hash>/`. The page render itself is cheap
  on a flat-file site, but the first hit that triggers a large-source resize can spike
  memory and wall time. Set `memory_limit` and `max_execution_time` for that worst-case
  thumb job, not the average page. Because those `/media/` responses are static and
  cache hard (deliberately *not* a preset bypass URI), the expensive generation happens
  once and every later request is served from disk.

## See also

- [`docs/wagtail.md`](wagtail.md) — the other lazy-session preset (Django), same shape
- [`docs/frameworks.md`](frameworks.md) — why Laravel/Django themselves get no preset
- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/README.md`](README.md) — all presets, and the apps we deliberately reject
