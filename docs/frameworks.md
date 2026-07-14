# Frameworks (Django, Laravel, Rails, …) + cache-turbo

**There is no `django` preset, no `laravel` preset, and there never will be.** Not
an oversight — a framework is not a cacheable thing. This page explains why, and
then hands you the thing a preset would have been: a procedure for deriving the
correct rule for *your* app, and a vhost that is safe before you derive anything.

If you are here because you run a specific *application* that happens to be built
on a framework — Discourse is Rails, Magento is Symfony — **use that app's
preset**, not this page. See [README.md](README.md).

- [Why there is no framework preset](#why-there-is-no-framework-preset)
- [Start here: the safe default](#start-here-the-safe-default)
- [Deriving your own rule (the 3 curls)](#deriving-your-own-rule-the-3-curls)
- [Per-framework field notes](#per-framework-field-notes)
- [Vhost](#vhost)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)

## Why there is no framework preset

A preset is three literals: cookie substrings, URI prefixes, query-arg keys. An
*application* can supply all three because it ships a fixed cookie name and a fixed
URL layout. A *framework* supplies none of them.

| | An app (WordPress) | A framework (Django/Laravel) |
|---|---|---|
| Cookie name | `wordpress_logged_in_<hash>` — fixed by the app | app- or env-derived; see below |
| Admin URI | `/wp-admin/` — fixed by the app | `/admin/` is one line of `urls.py` away from `/manage/`; Laravel has **no** default at all |
| Anonymous surface | blog posts — knowable | **undefined.** A Django install is a blog *or* a bank |

The rejection test from [README.md](README.md#apps-we-deliberately-do-not-ship-a-preset-for)
is *"what fraction of this app's requests are pages a logged-out stranger can see,
that look the same for every logged-out stranger?"* For an app that question has an
answer. For a framework it is **not a question about the framework** — it is a
question about the code someone wrote on top of it. We cannot answer it from here,
and a preset that pretends to would be an [attractive
nuisance](README.md#apps-we-deliberately-do-not-ship-a-preset-for): it would imply
we had checked, when only you can check.

And the one rule a framework preset *could* plausibly ship — "bypass on the session
cookie" — is broken on both of the big two, for two different reasons:

- **Laravel's session cookie is not called `laravel_session` on your site.** It is
  `Str::slug(env('APP_NAME'), '_') . '_session'` — so a real install emits
  `acme_shop_session`. `laravel_session` only appears if `APP_NAME` is unset, and
  the skeleton `.env` ships `APP_NAME=Laravel`. A shipped `laravel_session`
  substring would match **almost no production Laravel site**. Same failure class as
  [Joomla](joomla.md) and [Drupal](drupal.md): a per-install name is not a shippable
  literal.
- **…and even the right name would be useless, because Laravel cookies every
  guest.** `StartSession::addCookieToResponse()` gates only on *"is a session driver
  configured"* — there is no empty-or-modified check. Every anonymous visitor to any
  `web`-middleware route gets a session cookie on the **first** response. A bypass on
  it bypasses **100% of traffic**. This is the [`_sid` trap from
  phpBB](phpbb.md) and the [`MoodleSession` trap](README.md#apps-we-deliberately-do-not-ship-a-preset-for),
  wearing a Laravel hat.

Django is the interesting one, because a Django rule *can* work — conditionally,
which is precisely why it cannot be a preset. See below.

**CSRF cookies are never a bypass signal.** Django's `csrftoken` and Laravel's
`XSRF-TOKEN` are handed to **anonymous** visitors by design — any page rendering a
form (a search box in the header is enough) sets one. They are the single most
tempting wrong answer here: stable name, framework-level, and utterly guest-issued.
Bypassing on `csrftoken` zeroes your hit rate and finds no logged-in user. This is
the same rule the app presets encode as *"a cookie the app issues to guests can
never be a bypass."*

## Start here: the safe default

Before you know anything about your app, this is correct and costs you nothing:

```nginx
cache_turbo               ct;
cache_turbo_cache_control honor;      # <- the whole safety story
```

`honor` refuses to **store** any response carrying `private`, `no-cache` or
`no-store`. You do not need a preset to switch it on — `cache_turbo_backend`
merely *implies* it, and with no applicable preset you set it yourself. That single
directive is what makes several frameworks safe with no cookie rule at all, exactly
as it does for [Drupal](drupal.md):

- **ASP.NET Core** writes `Cache-Control: no-cache,no-store` on the very response
  that sets the session cookie (`SessionMiddleware.SetCookie()`), and on cookie-auth
  responses. Strongest origin backstop of any framework here.
- **Symfony** marks the response `private` whenever the session is started.
- **Next.js** (App Router) sends `private, no-cache, no-store, max-age=0,
  must-revalidate` on any dynamically-rendered route — and reading `cookies()` is
  what *makes* a route dynamic. Static/ISR routes stay cacheable, which is the
  correct split.

**Do not assume it for Django, Laravel, Rails, Flask or Express.** None of them
reliably marks an authenticated response `private` out of the box. On those,
`honor` is a backstop that may not fire, so the cookie rule you derive below is the
*primary* defence, not a belt-and-braces extra.

> **`Vary: Cookie` is not `Cache-Control: private`.** Django and Flask both add
> `Vary: Cookie` when the session is merely *accessed*. That is a keying
> instruction, not a do-not-store instruction — it does **not** stop a cache
> storing an authenticated page. Seeing `Vary: Cookie` in a response is not
> evidence you are safe.

## Deriving your own rule (the 3 curls)

The question a preset would answer for you is *"which cookie means logged in?"*
Answer it empirically, against **your** app, in three commands. Do this before you
write a single `cache_turbo_bypass`.

**1. What does a logged-OUT stranger get?** Anything here is disqualified as a
bypass signal — by definition, it does not mean "logged in".

```bash
curl -sI https://example.com/ | grep -i set-cookie
# Django:  Set-Cookie: csrftoken=...            <- guest cookie, NOT a bypass
# Laravel: Set-Cookie: acme_session=...         <- guest cookie, NOT a bypass
#          Set-Cookie: XSRF-TOKEN=...           <- guest cookie, NOT a bypass
# ideal:   (no output)                          <- every cookie below is meaningful
```

**2. What does a logged-IN user get that the stranger did not?** That difference —
and only that difference — is your bypass signal.

```bash
curl -s -c jar.txt -b jar.txt -X POST https://example.com/login \
     -d 'username=you&password=...' -o /dev/null
grep -vE '^#|^$' jar.txt | awk '{print $6}'
# Django on a brochure site:  csrftoken  sessionid   <- sessionid is new => that's it
# Laravel:                    acme_session XSRF-TOKEN <- SAME NAMES as step 1 => useless
```

If step 2's cookie names are identical to step 1's, **you have no presence-based
signal at all** and must key on a *value* (see [phpbb.md](phpbb.md), which has the
same problem and shows the `map` that solves it) — or bypass on a URI prefix
instead.

**3. Does the origin protect you anyway?** Ask the logged-in session for a page a
guest can also see.

```bash
curl -sI -b jar.txt https://example.com/ | grep -i cache-control
# Cache-Control: private, ...   <- honor mode refuses to store it. You have a net.
# (nothing)                     <- YOU HAVE NO NET. The cookie rule is load-bearing.
```

Then wire the answer up. If step 2 gave you a distinct name, e.g. Django's
`sessionid`:

```nginx
cache_turbo_bypass   $cookie_sessionid;
cache_turbo_no_store $cookie_sessionid;
```

If the name is per-install or hyphenated, use a `map` on `$http_cookie` — and read
the [hyphen gotcha](#gotchas) first, it will bite you.

## Per-framework field notes

Verified against framework source, not from memory. **The "guest cookie?" column is
the one that decides everything.**

| Framework | Session cookie | Stable name? | Set for a **guest**? | Origin sends `private`? |
|---|---|---|---|---|
| **Django** | `sessionid` | ✅ | **⚠️ only if something writes the session** — see below | ❌ no (only `Vary: Cookie`) |
| **Laravel** | `<APP_NAME>_session` | ❌ **env-derived** | ❌ **yes, always, unconditionally** | ❌ no |
| **Rails** | `_<appname>_session` | ❌ **per-app** | ⚠️ lazy, but flash + CSRF usually trip it | ❌ not guaranteed |
| **Symfony** | `PHPSESSID` | ✅ (but collides — see below) | ⚠️ lazy in theory, leaky in practice | ✅ **yes, on session start** |
| **Flask** | `session` | ✅ (but dangerously generic) | ⚠️ only if session written (`flash()` writes) | ❌ no (only `Vary: Cookie`) |
| **Express** | `connect.sid` | ✅ | ❌ **yes — `saveUninitialized: true` is the default** | ❌ no |
| **ASP.NET Core** | `.AspNetCore.Identity.Application` (auth) | ✅ | ✅ **no — set only on sign-in** | ✅ **yes, `no-cache,no-store`** |
| **Next.js** | *none* — library-defined | ❌ | library-dependent | ✅ on dynamic routes |

**Django — the conditional one.** `SessionMiddleware` sets `sessionid` only when the
session is **non-empty AND modified**. So a brochure site with no cart, no guest
flash messages and `CSRF_USE_SESSIONS=False` **never cookies a guest**, and
`cache_turbo_bypass $cookie_sessionid;` is exactly right. But it silently stops
being right the moment the app grows:

- an **anonymous cart** (`request.session['cart'] = …`) — cookies every guest;
  every Django shop does this
- **`django.contrib.messages`** — a *large* guest flash overflows cookie storage
  and falls back to the **session**, cookieing the guest
- **`CSRF_USE_SESSIONS = True`** — now every guest who sees a form gets `sessionid`
- **`SESSION_SAVE_EVERY_REQUEST = True`**

Each turns your bypass into a 100%-bypass and your hit rate into zero. Nothing
errors; the cache just quietly stops working. **That fragility is the entire reason
this is not a preset** — we would be shipping a rule whose correctness depends on
code we have never seen. Re-run curl #1 after any significant deploy.

**Symfony — do not bypass on `PHPSESSID`.** Same collision that keeps `SESS` out of
the [Drupal preset](drupal.md): the registry matches a substring of the whole
`Cookie` header, and `PHPSESSID` is the stock name for *every* PHP app on the host.
You would bypass co-hosted apps that are not even Symfony. Symfony's saving grace
is that it marks the response `private` on session start, so `honor` covers you —
lean on that, and add a URI bypass for your admin path.

**Flask — `session` is too generic to match safely.** A substring rule for `session`
hits `laravel_session`, `_forum_session`, `xf_session`, `PHPSESSID`… everything.
Rename it (`SESSION_COOKIE_NAME = 'myapp_sid'`) and bypass the distinctive name.

**Rails / Next.js — the name is not knowable from here.** Rails derives it from the
app name; Next.js has no session at all (Auth.js uses `next-auth.session-token`,
which becomes `__Secure-next-auth.session-token` **over HTTPS** — the name changes
between schemes, so a naive literal breaks in production but works in dev). Derive
with the curls.

## Vhost

Django + gunicorn, with the derived rule. The shape is the same for any framework —
swap the cookie name for the one **your** curl #2 produced.

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    server {
        listen 443 ssl http2;
        server_name example.com;

        location / {
            cache_turbo               ct;

            # No preset applies. Turn the origin backstop on by hand --
            # cache_turbo_backend would have implied this, but there is no
            # backend to name. On Django this is a WEAK net (Django does not
            # send `private`), so the bypass below is the real defence.
            cache_turbo_cache_control honor;

            # THE derived rule. Verified with curl: a logged-out GET does not
            # set `sessionid`. Re-verify after adding a cart or guest flash
            # messages -- either one cookies guests and silently zeroes the
            # hit rate. See docs/frameworks.md.
            cache_turbo_bypass        $cookie_sessionid;
            cache_turbo_no_store      $cookie_sessionid;

            # NOT $cookie_csrftoken -- Django hands that to anonymous visitors,
            # so bypassing on it would bypass everything.

            cache_turbo_valid         60s;
            cache_turbo_valid         404 410 1m;
            cache_turbo_preset        balanced;

            proxy_pass http://127.0.0.1:8000;
            proxy_set_header Host              $host;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # App-defined dynamic surfaces. A preset would have shipped these --
        # since none can, YOU must. Every private route needs a line here.
        location ^~ /admin/    { cache_turbo off; proxy_pass http://127.0.0.1:8000; }
        location ^~ /accounts/ { cache_turbo off; proxy_pass http://127.0.0.1:8000; }
        location ^~ /api/      { cache_turbo off; proxy_pass http://127.0.0.1:8000; }

        # Hashed static assets (collectstatic / ManifestStaticFilesStorage).
        location ^~ /static/ {
            cache_turbo off;
            alias /var/www/app/static/;
            expires 30d;
            access_log off;
        }

        # User uploads are frequently permission-checked. Do not cache blindly.
        location ^~ /media/ { cache_turbo off; alias /var/www/app/media/; }

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

> **Verify with `GET`, not `curl -sI`.** A `HEAD` response is served but **never
> stored**, so `curl -sI` shows `MISS` forever no matter how correct your config
> is — you will conclude the cache is broken when it is fine. Use `curl -s -D-`
> (GET, headers shown) throughout. Better still, watch the **body**: point at a URL
> whose content changes per request, and an unchanged body on the second GET is
> proof it came from cache.

```bash
# anonymous page: MISS then HIT  (GET -- -I would never HIT)
curl -s -D- -o /dev/null https://example.com/ | grep -i x-cache-turbo
curl -s -D- -o /dev/null https://example.com/ | grep -i x-cache-turbo   # HIT

# admin: BYPASS
curl -s -D- -o /dev/null https://example.com/admin/ | grep -i x-cache-turbo

# THE ONE THAT MATTERS: logged in, on a URL a guest can also fetch.
# Must be BYPASS. If it is ever HIT you are serving one user's page to another.
curl -s -D- -o /dev/null -b jar.txt https://example.com/ | grep -i x-cache-turbo

# THE OTHER ONE THAT MATTERS, and the one people skip: has the bypass
# accidentally become universal? A guest must NOT be bypassed.
curl -s -D- -o /dev/null https://example.com/ | grep -i x-cache-turbo
# BYPASS here => your "logged-in" cookie is being handed to guests.
# Hit rate is zero and the cache is doing nothing. Re-run the 3 curls.
```

The strongest form of the logged-in check does not trust the status header at all —
it compares **bodies**, because a leak is defined by bytes, not by a label:

```bash
curl -s https://example.com/ > guest.html                 # warm the cache
curl -s -b jar.txt https://example.com/ > user.html       # same URL, logged in
grep -qi 'log out\|your account' user.html \
  && ! diff -q guest.html user.html >/dev/null \
  && echo "OK: user got their own page, not the cached guest one"
```

If `user.html` is byte-identical to `guest.html`, the logged-in user was served the
**cached anonymous page** — the bypass is not firing. That is the failure this whole
page exists to prevent, and it is invisible if you only read `x-cache-turbo`.

That last check is the framework-specific one. On an app preset a guest bypass is
near-impossible; here it is the **default failure mode**, because the cookie you
bypassed on may be issued to everyone. Put it in your monitoring — a cache that
silently stopped caching looks exactly like a cache that is working, until the
origin falls over.

## Gotchas

- **`$cookie_<name>` does not translate `-` to `_`.** Unlike headers. So
  `$cookie_XSRF_TOKEN` **never matches** `XSRF-TOKEN` — no error, just a
  permanently empty variable, and a bypass that never fires. Any hyphenated cookie
  (`XSRF-TOKEN`, `next-auth.session-token`) can only be read with a `map` on
  `$http_cookie`. Dots are just as bad. This has bitten us before; see
  [magento.md](magento.md).
- **`HEAD` responses are never stored, so `curl -sI` can never show a `HIT`.** It
  will report `MISS` on a perfectly working cache, forever. Debug with `curl -s -D-`
  (GET). This one costs people an afternoon. (`curl -sI` is still the right tool for
  the [3 curls](#deriving-your-own-rule-the-3-curls) above — those read `Set-Cookie`
  and `Cache-Control`, which HEAD returns correctly. It is only the **cache-status**
  checks that need a GET.)
- **A `map` needs PCRE.** If you build nginx `--without-http_rewrite_module`, a
  regex `map` **parses fine** — `nginx -t` says *successful* — and then never
  matches anything, ever. Silent. Check `nginx -V` for `--with-pcre` before
  debugging a `map` that "does nothing".
- **Do not bypass on the CSRF cookie.** Bears repeating: `csrftoken` /
  `XSRF-TOKEN` are guest cookies. This is the most common way to get a 0% hit rate
  and think you have configured security.
- **Do not put the session cookie in `cache_turbo_key`.** One entry per visitor
  (hit rate ≈ 0) *and* authenticated HTML in the cache. Neither safe nor fast. See
  [README.md — the rule the presets encode](README.md#the-rule-the-presets-encode).
- **`cache_turbo_backend generic`/`auto` are hard config errors**, not a fallback
  for "framework, no preset". There is no union preset. The correct spelling for
  *"cache this, no preset applies"* is simply to omit `cache_turbo_backend` and set
  `cache_turbo_cache_control honor;` yourself.
- **A framework in a subdirectory breaks prefix rules.** URI prefixes anchor at
  position 0. If the app is mounted at `/shop/`, `/admin/` is `/shop/admin/` and
  your `location ^~ /admin/` never fires.
- **Re-derive after deploys.** The Django conditions above are code-dependent, not
  config-dependent — a developer adding an anonymous cart changes your cache's
  correctness without touching nginx. Nobody will tell you.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are never
  cached, regardless of any of this. Those floors hold even if every rule above is
  wrong.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend) — the preset table
- [`docs/README.md`](README.md) — all presets, and the apps we deliberately reject
- [`docs/phpbb.md`](phpbb.md) — the other guide with **no** shippable cookie rule and no origin net; shows the value-testing `map`
- [`docs/drupal.md`](drupal.md) — the `honor`-carries-it pattern, and the `SESS`/`PHPSESSID` collision
- [`docs/magento.md`](magento.md) — the `$cookie_` hyphen trap in full
