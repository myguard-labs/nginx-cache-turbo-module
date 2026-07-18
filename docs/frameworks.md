# Frameworks (Django, Laravel, Rails, …) + cache-turbo

_Last researched: 2026-07-18_

**There is no `django` preset, no `laravel` preset, and there never will be.** Not
an oversight — a framework is not a cacheable thing. This page explains why, and
then hands you the thing a preset would have been: a procedure for deriving the
correct rule for *your* app, and a vhost that is safe before you derive anything.

If you are here because you run a specific *application* that happens to be built
on a framework — Discourse is Rails, Magento is Laminas/Zend — **use that app's
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
  derived from `APP_NAME` in `config/session.php`, and the exact derivation has also
  *changed between framework versions*. Laravel 11 shipped
  `Str::slug(env('APP_NAME', 'laravel'), '_') . '_session'` — underscores — so an
  `APP_NAME=Acme Shop` install emitted `acme_shop_session`. Laravel 12 rewrote that
  default (dropping the `'_'` separator so `Str::slug` falls back to its hyphen, and
  suffixing `-session`; some 12.x point releases briefly used `Str::snake`, see
  [laravel/framework#56449](https://github.com/laravel/framework/issues/56449)), so a
  current install more typically emits the **hyphenated** `acme-shop-session`. Either
  way `laravel_session` only appears when `APP_NAME` is unset. A shipped
  `laravel_session` substring would match **almost no production Laravel site** — and
  the modern hyphenated name additionally cannot be read with `$cookie_` at all (see
  the [hyphen gotcha](#gotchas)). Same failure class as [Joomla](joomla.md) and
  [Drupal](drupal.md): a per-install (now also per-version) name is not a shippable
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
| **Laravel** | `<APP_NAME>_session` (11.x) / `<APP_NAME>-session` (12.x) | ❌ **env- & version-derived** | ❌ **yes, always, unconditionally** | ❌ no |
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

## Two engines the presets have that you can now use directly

A preset is three literal lists (bypass cookies, bypass URIs, dynamic query
args) plus, for a few, two engines that plain nginx config could not express.
Since v15 both engines are available as directives, so a hand-configured site
gets exactly what a preset gets — no preset required.

### `cache_turbo_bypass_uri` — segment-boundary URI bypass

```nginx
cache_turbo_bypass_uri  /admin  /account/;
```

Skips the cache entirely (origin, never captured) for any request whose URI
matches a listed prefix **on a path-segment boundary** — the byte after the
prefix must be `/`, `.`, or end-of-string. So `/admin` bypasses `/admin`,
`/admin/users`, and `/admin.php`, but **not** `/administrator` (the letters
continue past the needle — a different resource). A needle ending in `/`
(`/account/`) carries its own boundary and bypasses the whole subtree.

This is the one thing a plain nginx `location` prefix cannot do: `location`
prefixes anchor at position 0 and have no boundary semantics, so a `location`
that bypasses `/admin` also swallows `/administrator`, and mounting the app in a
subdirectory silently mis-matches. Use `cache_turbo_bypass_uri` and mount-depth
stops mattering.

Prefixes must start with `/`. It works with or without a `cache_turbo_backend`
preset — in pure manual mode it is your whole URI-bypass surface.

### `cache_turbo_key_cookie` — fold a cookie's VALUE into the key

```nginx
cache_turbo_key_cookie  X-Segment;
```

Value-keys the named cookie: visitors carrying **different values** get
**different cache entries**, visitors sharing a value share one entry, and a
visitor with **no cookie** gets the plain anonymous entry. This is the
[magento](magento.md)/[shopware6](shopware6.md) tier-3 engine as a directive.

Use it **only** for a cookie that is a *segment fingerprint* — a marker of which
shared variant of a page to serve (customer group, currency, store view, A/B
bucket) that many visitors legitimately share — **never** for an identity cookie
(a session id, a login token). Keying on an identity cookie gives one entry per
visitor (hit rate ≈ 0) and puts authenticated HTML in a shared cache. For an
identity cookie you want `cache_turbo_bypass`, not this.

Why a directive and not just `cache_turbo_key $cookie_x`:

- The name is matched **EXACTLY** and **every** `Cookie:` header is scanned, so
  a client cannot hide the real cookie in a second header (or use a name that
  merely ends with yours) to choose which cache bucket it reads or writes.
- The value is folded with an **unforgeable length-prefixed framing**, so no
  cookie value can splice itself into a neighbouring key field — a plain
  delimiter in `cache_turbo_key` *is* forgeable (nginx permits the `0x1f`
  separator byte inside header values).
- It also reads **hyphenated cookie names** (`X-Magento-Vary`, `sw-cache-hash`)
  that `$cookie_<name>` silently cannot — see the `$cookie_` trap below.

The Set-Cookie store floor covers the transition race for free: a request with
no key cookie keys to the anonymous entry, and if the response *establishes* the
segment (`Set-Cookie: X-Segment=...`) that response is never stored, so it can
never poison the anonymous entry.

## Gotchas

- **`$cookie_<name>` does not translate `-` to `_`.** Unlike headers. So
  `$cookie_XSRF_TOKEN` **never matches** `XSRF-TOKEN` — no error, just a
  permanently empty variable, and a bypass that never fires. Any hyphenated cookie
  (`XSRF-TOKEN`, `next-auth.session-token`) can only be read with a `map` on
  `$http_cookie`. Dots are just as bad. This has bitten us before; see
  [magento.md](magento.md). If you need to value-KEY such a cookie (a segment
  fingerprint, not an identity), [`cache_turbo_key_cookie`](#cache_turbo_key_cookie--fold-a-cookies-value-into-the-key)
  reads hyphenated/dotted names natively and skips the `map` entirely.
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
- **A framework in a subdirectory breaks `location` prefix rules.** A `location`
  prefix anchors at position 0. If the app is mounted at `/shop/`, `/admin/` is
  `/shop/admin/` and your `location ^~ /admin/` never fires — and a `location`
  matching `/admin` also swallows `/administrator`.
  [`cache_turbo_bypass_uri`](#cache_turbo_bypass_uri--segment-boundary-uri-bypass)
  fixes both: give it the real mounted paths and it matches on a segment
  boundary, so `/administrator` is left cacheable.
- **Re-derive after deploys.** The Django conditions above are code-dependent, not
  config-dependent — a developer adding an anonymous cart changes your cache's
  correctness without touching nginx. Nobody will tell you.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are never
  cached, regardless of any of this. Those floors hold even if every rule above is
  wrong.

## Runtime settings / gotchas

The [3 curls](#deriving-your-own-rule-the-3-curls) tell you *which cookie* to key on.
This section is the layer under that: framework-specific origin behaviour that
suppresses caching, competes with the module, or needs tuning on the MISS path. Only
the gotchas that are particular to each framework are listed — the universal floors
(`Set-Cookie` never stored, `Authorization` never cached) hold everywhere.

**Laravel (PHP).** Both cookies it sets are guest cookies: the session cookie
(`StartSession::addCookieToResponse()` gates only on *a session driver being
configured*, so every `web`-middleware response cookies the visitor) and `XSRF-TOKEN`
(written whenever the encrypt-cookies middleware runs — i.e. on GETs that render a
form). There is no config knob to make the `web`-group session lazy, so you **cannot**
key on presence — lean on `cache_turbo_cache_control honor;` (weak here: Laravel does
not send `private`) plus a URI bypass of the authenticated area. Never fold either
cookie into the key; `XSRF-TOKEN` is hyphenated, so `$cookie_XSRF_TOKEN` reads empty
and `cache_turbo_key_cookie` is the only thing that could read it — which you must not
do for a guest token anyway. Origin MISS latency is opcache-bound: enable OPcache with
`opcache.validate_timestamps=0` in production (the module serves HITs itself, so
opcache only pays on the MISS).

**Symfony (PHP).** `PHPSESSID` (or the configured `framework.session.name`) is the
stock PHP name shared by every co-hosted PHP app, so a substring bypass on it hits
neighbours that are not even Symfony — do **not** bypass on it. Symfony's saving grace
is `AbstractSessionListener`: it stamps the response `private` the moment the session
is *started*, so `cache_turbo_cache_control honor;` genuinely covers authenticated
pages (add a URI bypass for the admin path as belt-and-braces). Two traps: (1) an app
that opts a session-bearing response back into caching via
`AbstractSessionListener::NO_AUTO_CACHE_CONTROL_HEADER` drops that `private` — audit
for it. (2) Symfony ships its *own* PHP reverse proxy (`framework.http_cache: true`,
visible via the `X-Symfony-Cache` header); running it behind cache-turbo gives you two
stacked gateway caches with two TTLs. Pick one edge — usually disable
`framework.http_cache` and let cache-turbo be the cache. Opcache tuning as for Laravel.

**Rails (Ruby).** The cookie is `_<app>_session`, per-app (from
`config/session_store.rb`), and the session is lazy — but the CSRF `authenticity_token`
lives *in the session* by default, so the first form render starts it and cookies the
guest. Rails 7+ can move the CSRF token out of the session into its own encrypted
cookie (`config.action_controller.urlsafe_csrf_tokens` / storing it outside the
session): that stops session-thrash from anonymous CSRF but *adds a distinct guest
cookie* — re-run curl #1, do not bypass on it. Rails does not reliably send `private`,
so the derived cookie rule is load-bearing. `Rack::Cache` stopped being a default
dependency in **Rails 4**; if the app re-enables it (the `rack-cache` gem +
`config.action_dispatch.rack_cache = true`) you get a second HTTP cache — prefer
cache-turbo at the edge and leave `Rack::Cache` off. MISS throughput scales with Puma
workers (`WEB_CONCURRENCY`), not with the cache.

**Django (Python).** `csrftoken` is a guest cookie by design (any form-rendering GET
sets it) — never a bypass signal, never in the key. `sessionid` is set only on a
non-empty *modified* session, which is exactly the conditional the field notes above
warn about. Watch two settings that turn `sessionid` into a guest cookie:
`CSRF_USE_SESSIONS = True` (moves the CSRF token into the session, so every form-GET
now writes it) and `SESSION_SAVE_EVERY_REQUEST = True`. Session middleware also emits
`Vary: Cookie` whenever the session is *accessed* — that is a keying instruction, not
`private`, so `honor` will not fire on it and it is no evidence of safety. MISS
throughput scales with gunicorn workers, not the cache.

**Express (Node).** `connect.sid` is the express-session default, and
`saveUninitialized` **defaults to `true`** — which saves and cookies *every* anonymous
visitor, zeroing your hit rate. The single highest-value origin change is
`saveUninitialized: false`, so a guest who never writes the session is never cookied
and the response stays cacheable; presence of `connect.sid` then genuinely means
"has state". Express sends no `private` of its own, so the cookie/URI bypass is the
only defence. A CSRF layer (`csurf`, `csrf-csrf`) sets its own cookie on GET — keep it
out of the key. MISS throughput scales with the Node cluster / PM2 worker count.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend) — the preset table
- [`docs/README.md`](README.md) — all presets, and the apps we deliberately reject
- [`docs/phpbb.md`](phpbb.md) — the other guide with **no** shippable cookie rule and no origin net; shows the value-testing `map`
- [`docs/drupal.md`](drupal.md) — the `honor`-carries-it pattern, and the `SESS`/`PHPSESSID` collision
- [`docs/magento.md`](magento.md) — the `$cookie_` hyphen trap in full
