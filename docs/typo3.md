# TYPO3 + cache-turbo

Caching a TYPO3 (v11–v13) frontend. A lazy-session bypass preset — same shape
as [kirby](kirby.md) — but with a real, **fails-unsafe** caveat that the kirby
and wagtail presets do not have. Read the [one condition](#the-one-condition--and-why-it-is-not-safe)
section before you ship this.

- [The short version](#the-short-version)
- [What the preset matches](#what-the-preset-matches)
- [The one condition — and why it is NOT safe](#the-one-condition--and-why-it-is-not-safe)
- [`be_typo_user` is a separate risk, not a duplicate](#be_typo_user-is-a-separate-risk-not-a-duplicate)
- [Vhost](#vhost)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend typo3;     # implies cache_turbo_cache_control honor
```

That covers a stock install. **If your site overrides `FE/cookieName`, this is
not enough on its own** — see below, this is not optional reading.

## What the preset matches

| Check | Values |
|---|---|
| Cookie substrings | `fe_typo_user`, `be_typo_user` |
| URI prefixes | `/typo3` |
| Query args | — |

`fe_typo_user` is the frontend login cookie. `be_typo_user` is the backend
login cookie — matched too, and not redundant (see
[below](#be_typo_user-is-a-separate-risk-not-a-duplicate)).

**`/typo3`** is the backend entry point. Unlike Magento, TYPO3 does not
randomise it — it is a stable, shippable prefix across supported versions.

## The one condition — and why it is NOT safe

`FrontendUserAuthentication` sets `$dontSetCookie = true`
(`FrontendUserAuthentication.php:155`), **overriding** the base class default of
`false` (`AbstractUserAuthentication.php:199`). It is flipped back to `false` in
only two places, both on the login path: `createUserSession()` (`:242`) and
`regenerateSessionId()` (`:407`), gated by `shallSetSessionCookie()` (`:344`).
So an anonymous visitor reading public pages is issued **no cookie at all** —
upstream chose this specifically to make the frontend cacheable, and it is why
this preset is worth shipping: good hit rate on the common case.

**This is the same lazy-session shape as [kirby](kirby.md#the-one-condition--and-why-its-safe)
and [wagtail](wagtail.md) — but the failure direction here is the OPPOSITE, and
that asymmetry is the single most important thing on this page.**

The cookie **name** is admin-overridable, not a hard literal.
`FrontendUserAuthentication::getCookieName()` (`:167`) reads
`$GLOBALS['TYPO3_CONF_VARS']['FE']['cookieName']`, falling back to
`'fe_typo_user'` only if that is empty. This is **not** a per-install hash like
Drupal's `SESS<hash>` — it is a plain overridable default, and overriding it is
rare. But:

> **If a site sets `FE/cookieName`, this preset silently loses the match — and
> a lost match on a bypass rule means logged-in pages get cached and served to
> strangers.** Unlike kirby's `csrf()` condition or wagtail's guest-session
> condition, which fail toward a needless *bypass* (a lost hit, never a leak),
> a renamed TYPO3 frontend cookie fails toward exactly the opposite: the
> *cache* keeps working, the *safety check* silently stops. **This preset fails
> UNSAFE on that one condition. Every other conditional preset in this
> registry fails safe. This is the exception — treat it as such.**

If you set `FE/cookieName`, you **must** add your own bypass:

```nginx
cache_turbo_bypass $cookie_<your_cookie_name>;
```

Verify which name your install actually uses before going live:

```bash
grep -r "cookieName" typo3conf/ config/ 2>/dev/null
```

## `be_typo_user` is a separate risk, not a duplicate

`be_typo_user` is **not** redundant with the frontend cookie. An editor
previewing the frontend, or any backend user hitting a frontend page, carries
**only** the BE cookie — no `fe_typo_user` at all. TYPO3 renders hidden or
scheduled records and preview versions of content for such a user. Caching that
response would publish **unpublished content** to the next anonymous visitor.
This is the same class of hazard as XenForo's `xf_session_admin` — a separate
cookie, separate session table, independent lifetime from the primary session,
and it must be matched independently rather than assumed covered by the
frontend rule.

## Vhost

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    upstream fastcgi_backend { server unix:/run/php/php-fpm.sock; }

    server {
        listen 443 ssl http2;
        server_name example.com;
        root /var/www/typo3/public;

        location / {
            try_files $uri /index.php$is_args$args;
        }

        location ~ \.php$ {
            cache_turbo         ct;
            cache_turbo_backend typo3;    # implies cache_control honor

            cache_turbo_valid   60s;
            cache_turbo_valid   404 410 1m;
            cache_turbo_preset  balanced;

            include        fastcgi_params;
            fastcgi_param  SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_pass   fastcgi_backend;
        }

        # Only if you override FE/cookieName -- see "The one condition" above.
        # location ~ \.php$ {
        #     cache_turbo_bypass $cookie_your_renamed_cookie;
        # }

        location = /_cache {
            cache_turbo_admin on;
            allow 127.0.0.1;
            deny  all;
        }
    }
}
```

## Checking it works

> Use **GET**, not `curl -sI`. A `HEAD` response is never stored, so `-I`
> reports `MISS` forever on a perfectly working cache.

```nginx
add_header X-Cache-Turbo $cache_turbo_status always;
```

```bash
# anonymous page: MISS then HIT
curl -s -o /dev/null -D- https://example.com/some-page | grep -i x-cache-turbo
curl -s -o /dev/null -D- https://example.com/some-page | grep -i x-cache-turbo

# backend entry point: BYPASS
curl -s -o /dev/null -D- https://example.com/typo3 | grep -i x-cache-turbo

# logged-in frontend user must never be served from cache
curl -s -o /dev/null -D- -H 'Cookie: fe_typo_user=abc' https://example.com/some-page \
    | grep -i x-cache-turbo          # BYPASS

# backend-only session hitting a frontend page must also bypass
curl -s -o /dev/null -D- -H 'Cookie: be_typo_user=abc' https://example.com/some-page \
    | grep -i x-cache-turbo          # BYPASS

# THE OVERRIDE CHECK -- do this once per install, not just once ever.
# If FE/cookieName is set, this MUST show your renamed cookie, not fe_typo_user.
grep -r "cookieName" typo3conf/ config/ 2>/dev/null
```

## Gotchas

- **The renamed-cookie case is the whole risk on this page.** See
  [above](#the-one-condition--and-why-it-is-not-safe) — this preset fails
  unsafe, not safe, if `FE/cookieName` is overridden and you do not add your own
  `cache_turbo_bypass`.
- **`be_typo_user` guards preview/editor traffic on frontend URLs** — do not
  remove it from the preset thinking it only matters on `/typo3`. See
  [above](#be_typo_user-is-a-separate-risk-not-a-duplicate).
- **`/typo3` has no trailing slash in the preset but matches on a path-segment
  boundary** — it matches `/typo3`, `/typo3/`, `/typo3/module/...` but not an
  unrelated segment merely sharing the letters.
- **Don't set `cache_turbo_cache_control ignore`.** It overrides the `honor`
  that `cache_turbo_backend` implies.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached, regardless of preset. Those floors hold independently of the
  cookie-name risk above — they still catch the response that *sets* a renamed
  cookie for the first time, they just cannot catch a *subsequent* request that
  already carries it under a name the preset does not know.

## See also

- [`docs/kirby.md`](kirby.md) — the other lazy-session preset, but fails SAFE (contrast)
- [`docs/wagtail.md`](wagtail.md) — same shape again, also fails safe
- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/README.md`](README.md) — all presets
