# Wagtail + cache-turbo

_Last researched: 2026-07-18_

Caching a Wagtail (Django CMS) site. This is the first preset whose auth cookie
belongs to the **framework**, not the app — Wagtail ships no cookie of its own and
rides Django's `sessionid`.

That works, but **conditionally**, and the condition is your application code's to
break. Read [the condition](#the-condition-and-how-to-check-it) before you trust
it. If you are here about Django or Laravel *in general* rather than Wagtail
specifically, you want [frameworks.md](frameworks.md).

- [The short version](#the-short-version)
- [What the preset matches](#what-the-preset-matches)
- [The condition, and how to check it](#the-condition-and-how-to-check-it)
- [Vhost](#vhost)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)
- [Runtime settings / gotchas](#runtime-settings--gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend wagtail;     # implies cache_turbo_cache_control honor
```

## What the preset matches

| Check | Values |
|---|---|
| Cookie substrings | `sessionid` |
| URI prefixes | `/admin/`, `/django-admin/`, `/documents/` |
| Query args | — |

**`sessionid`, and deliberately not `csrftoken`.** Django's `SessionMiddleware`
writes the session cookie only when the session is **non-empty AND modified**, so a
logged-out reader of a public page is issued **no cookie at all** — that is the
whole reason this preset can exist. `csrftoken`, by contrast, is handed to *any*
anonymous visitor who renders a form (a search box in the header is enough).
Bypassing on it would bypass everything and still find no logged-in user. See the
[two traps](README.md#two-traps-these-guides-keep-pointing-at).

**The URI prefixes come from Wagtail's own project template**
(`project_template/project_name/urls.py`), so all three are what a stock install
actually serves:

- **`/admin/`** — the Wagtail admin. **Relocatable**; Wagtail's docs suggest `/cms/`
  when it clashes with Django admin. An install that moves it loses the URI
  shortcut but stays **correct**, because `sessionid` is the real guard. *The
  cookie guards; the URI optimises.* That ordering is deliberate.
- **`/django-admin/`** — also in the stock template.
- **`/documents/`** — **load-bearing, not decoration.** `WAGTAILDOCS_SERVE_METHOD`
  defaults to `serve_view` under `FileSystemStorage`: a Django view that enforces
  **per-collection privacy checks**. A private document fetched by an authorised
  user must never be stored and replayed to a stranger. The preset bypasses on the
  prefix rather than trusting a `no-store` header.

**`/search/` is deliberately absent.** It is dynamic, but **anonymous-identical** —
every logged-out visitor searching `foo` gets the same page — so it is shared, hot,
and exactly what a cache is for. Bypassing it would be a pure hit-rate loss with no
safety gain. (Same reasoning that keeps a blanket `action=` out of the
[mediawiki](mediawiki.md) preset.)

## The condition, and how to check it

`sessionid` means "logged in" **only while nothing writes to the session for
anonymous visitors.** Each of these breaks that, and every one is a normal thing to
add to a Django site:

| What you add | What happens |
|---|---|
| An **anonymous cart** (`request.session['cart'] = …`) | every guest gets `sessionid` |
| **`django.contrib.messages`** with a large guest flash | overflows cookie storage, **falls back to the session** → guest gets `sessionid` |
| **`CSRF_USE_SESSIONS = True`** | every guest who sees a form gets `sessionid` |
| **`SESSION_SAVE_EVERY_REQUEST = True`** | every guest with a non-empty session gets `sessionid` |

Each turns the bypass into a **100% bypass**: hit rate zero, no error, nothing in
the log. The cache silently stops caching, which looks exactly like a cache that is
working — until the origin falls over.

**This fails safe, which is the only reason it is shippable.** The error direction
is *bypass a guest* (lost hits), never *serve a member's page to a stranger* (a
leak). Compare Flarum, whose failure direction is the leak — which is why there is
[no flarum preset](README.md#apps-we-deliberately-do-not-ship-a-preset-for).

Check with one command, and **re-run it after any deploy that touches sessions**:

```bash
curl -sI https://example.com/ | grep -i set-cookie
# (no sessionid)          <- good, the preset works
# Set-Cookie: sessionid=  <- STOP. Your hit rate is zero. See below.
```

If a guest gets `sessionid`, you cannot use a presence rule. Either stop writing to
the session for anonymous users, or key on a *value* — see [phpbb.md](phpbb.md),
which has the same problem and shows the `map` that solves it.

## Vhost

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    server {
        listen 443 ssl http2;
        server_name example.com;

        location / {
            cache_turbo         ct;
            cache_turbo_backend wagtail;   # implies cache_control honor

            cache_turbo_valid   60s;
            cache_turbo_valid   404 410 1m;
            cache_turbo_preset  balanced;

            proxy_pass http://127.0.0.1:8000;
            proxy_set_header Host              $host;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Hashed by ManifestStaticFilesStorage -- long-lived, content-addressed.
        location ^~ /static/ {
            cache_turbo off;
            alias /var/www/app/static/;
            expires 30d;
            access_log off;
        }

        # NOTE: /media/ is Django's raw upload dir, NOT Wagtail's document view.
        # Wagtail images live here and are safe to cache; PRIVATE documents are
        # served through /documents/, which the preset already bypasses.
        location ^~ /media/ {
            alias /var/www/app/media/;
            expires 7d;
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

> Use **GET**, not `curl -sI`. A `HEAD` response is never stored, so `-I` reports
> `MISS` forever on a perfectly working cache.

```bash
# anonymous page: MISS then HIT
curl -s -D- -o /dev/null https://example.com/            | grep -i x-cache-turbo
curl -s -D- -o /dev/null https://example.com/            | grep -i x-cache-turbo

# admin + documents: BYPASS
curl -s -D- -o /dev/null https://example.com/admin/      | grep -i x-cache-turbo
curl -s -D- -o /dev/null https://example.com/documents/3/x.pdf | grep -i x-cache-turbo

# logged-in editor must never be served from cache
curl -s -D- -o /dev/null -H 'Cookie: sessionid=abc' https://example.com/ \
    | grep -i x-cache-turbo          # BYPASS

# THE ONE PEOPLE SKIP: a guest carrying csrftoken must still HIT.
# BYPASS here means your hit rate is zero.
curl -s -D- -o /dev/null -H 'Cookie: csrftoken=xyz' https://example.com/ \
    | grep -i x-cache-turbo          # HIT

# And the guest-cookie check from above -- the one that decides everything.
curl -sI https://example.com/ | grep -i set-cookie      # must NOT set sessionid
```

## Gotchas

- **Re-check after deploys.** The condition above is *code*-dependent, not
  config-dependent. A developer adding an anonymous cart silently zeroes your hit
  rate without touching nginx, and nobody will tell you. Put the `set-cookie` check
  in monitoring.
- **Moving the admin is fine.** If you relocate `/admin/` to `/cms/`, add a
  `cache_turbo_bypass` (or just rely on `sessionid`, which still catches every
  authenticated request). You lose an optimisation, not a guarantee.
- **`/documents/` must stay bypassed.** If you switch `WAGTAILDOCS_SERVE_METHOD` to
  `direct` or `redirect`, documents are served by the storage backend and the
  privacy check moves — but the preset's bypass costs you nothing, so leave it.
- **Don't set `cache_turbo_cache_control ignore`.** It overrides the `honor` that
  `cache_turbo_backend` implies, and `honor` is what keeps Django's `never_cache`
  admin responses out of the cache if a URI rule ever misses.
- **`/admin/` is not a reserved word.** It is an ordinary route that a non-Wagtail
  site may serve as a perfectly cacheable page — which is exactly why no preset is
  ever enabled implicitly. Name it.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are never
  cached, regardless of preset. Those floors hold.

## Runtime settings / gotchas

Wagtail is Django on Python — it runs under a WSGI/ASGI server, not PHP-FPM — so the
operational levers are different from the PHP presets. These are Wagtail/Django-specific.

- **`Vary: Cookie` is emitted the moment the session is *touched*.** Django's
  `SessionMiddleware` adds `Vary: Cookie` to any response whose session was merely
  *accessed*, not just written — and `@login_required`, reading `request.user`, and
  Wagtail's own middleware all read the session, so most non-trivial views carry it.
  `CsrfViewMiddleware` adds the same header whenever the `{% csrf_token %}` tag
  renders. It is a keying instruction, **not** a `Cache-Control: private`; it does
  not stop a store. **With `cache_turbo_auto_vary off` (the default) the module
  ignores the response `Vary` and classifies the request per the preset's
  `sessionid` bypass rule — which is exactly what you want here:** an anonymous
  page carries no `sessionid`, so it is not bypassed and caches correctly
  regardless of a stray `Vary: Cookie`. Do
  **not** reflexively enable `cache_turbo_auto_vary` for a Wagtail origin — auto-Vary
  treats `Vary: Cookie` as *uncacheable*, so turning it on would make every public
  page that renders a form (a header search box is enough) stop caching entirely.
  The cookie rule is the guard; leave Vary blind. (Verified: Django middleware +
  CSRF docs.)
- **`csrftoken` on GET pages is fine — keep it lazy, don't force it.** The preset
  deliberately does not bypass on `csrftoken`, so a guest carrying it still HITs. The
  risk is upstream: if the origin sets `csrftoken` (and the accompanying
  `Vary: Cookie`) *unconditionally* on every GET, you forfeit the option to ever
  enable auto-Vary and widen the cookie surface for no gain. Render the token only
  where a form actually needs it rather than site-wide, and set
  `CSRF_COOKIE_HTTPONLY = True` as defence-in-depth (it does not affect caching, but
  keeps the cookie out of JavaScript). Avoid `CSRF_USE_SESSIONS = True`, which — per
  the [condition table](#the-condition-and-how-to-check-it) — promotes every
  form-viewing guest to a `sessionid` and zeroes the hit rate.
- **`DEBUG = False` in production.** `DEBUG = True` changes response behaviour
  (verbose error pages, different static handling) and is never what you want behind
  a full-page cache. Confirm it before trusting any measurement.
- **Tune the WSGI/ASGI worker pool, not FPM.** Wagtail serves through gunicorn (WSGI)
  or uvicorn (ASGI), so concurrency is a gunicorn/uvicorn setting — roughly
  `2 × cores + 1` sync workers as a starting point — and `--preload` lets workers
  share the loaded application image, which trims memory and avoids each worker
  cold-starting the ORM on a cache-stampede MISS. There is no `pm.max_children` here.
- **`wagtail-cache` overlaps this module — pick one full-page cache.** The
  third-party `wagtail-cache` package (CodeRed) is a *server-side* Django-cache page
  cache: it refuses to cache logged-in responses or anything carrying
  `Cache-Control: no-cache`/`private`, and emits its own `Cache-Control`. If you keep
  it, cache-turbo's `honor` mode (which `cache_turbo_backend wagtail` already implies)
  respects those headers — but running both is redundant double-caching. For an
  nginx-fronted deployment, let cache-turbo own the full-page cache and drop
  `wagtail-cache`; if you must keep it, do not set `cache_turbo_cache_control ignore`,
  or you would override the very headers it relies on.
- **Purge cache-turbo on publish with `wagtail.contrib.frontend_cache`.** Wagtail's
  built-in front-end cache invalidator ships signal handlers that purge a reverse
  proxy whenever a page is published or deleted. Its `HTTPBackend` sends an HTTP
  `PURGE` request to the configured `LOCATION` — exactly the shape cache-turbo accepts
  once you set `cache_turbo_purge on`. Point `LOCATION` at the nginx origin (a direct
  connection, no intermediate proxy, per Wagtail's docs) and publishing a page drops
  its entry from L1 (and L2):

  ```python
  WAGTAILFRONTENDCACHE = {
      'default': {
          'BACKEND':  'wagtail.contrib.frontend_cache.backends.HTTPBackend',
          'LOCATION': 'http://127.0.0.1',
      },
  }
  ```

  The backend purges one URL per page by default; override `get_cached_paths()` on a
  page model if a page resolves to several URLs.

## See also

- [`docs/frameworks.md`](frameworks.md) — Django/Laravel in general, and why *they* get no preset
- [`docs/kirby.md`](kirby.md) — the other lazy-session preset, same shape
- [`docs/phpbb.md`](phpbb.md) — the value-testing `map`, if a guest ever gets `sessionid`
- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/README.md`](README.md) — all presets
