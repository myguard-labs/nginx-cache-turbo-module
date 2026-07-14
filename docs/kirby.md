# Kirby + cache-turbo

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
| Cookie substrings | `kirby_session` |
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
        location ~ ^/(content|site|kirby)/ {
            deny all;
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
  never matches — silently. Add your own `cache_turbo_bypass $cookie_<newname>;`.
- **Kirby's own page cache is a different layer.** It lives in PHP and makes the
  origin fast, which is what your cache-turbo *misses* hit. Leave it on; the two
  compose.
- **`/panel` has no trailing slash in the preset, but matches on a path-segment
  boundary.** The prefix matches `/panel`, `/panel/`, and `/panel/pages` — but
  NOT a different segment that merely shares the letters, such as
  `/panels-and-doors` (which caches normally). The rule is: after the prefix the
  URL must end or continue with `/` or `.`. If you relocate the panel via
  `panel.slug`, add a `cache_turbo_bypass` — though `kirby_session` still guards
  every authenticated request, so you lose an optimisation, not a guarantee.
- **Don't set `cache_turbo_cache_control ignore`.** It overrides the `honor` that
  `cache_turbo_backend` implies.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are never
  cached, regardless of preset. Those floors hold — and they are why a page that
  *issues* `kirby_session` is never captured in the first place.

## See also

- [`docs/wagtail.md`](wagtail.md) — the other lazy-session preset (Django), same shape
- [`docs/frameworks.md`](frameworks.md) — why Laravel/Django themselves get no preset
- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/README.md`](README.md) — all presets, and the apps we deliberately reject
