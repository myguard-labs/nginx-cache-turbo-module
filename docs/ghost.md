# Ghost + cache-turbo

_Last researched: 2026-07-18_

Caching a Ghost (5.x/6.x) blog. Ghost is a clean fit for one reason only: an
anonymous reader gets **no cookie at all**, so the whole public blog is a large,
genuinely shared surface and every anonymous reader can be served the same
cached page.

**Do not reason "a member sees the same HTML as a guest on a public post."** It
is false. `@member` is injected into the template context unconditionally
whenever `req.member` exists (`update-local-template-options.js`), so a stock
`{{#if @member}}` in the theme changes the markup of a *fully public* post.
Ghost itself agrees — `frontend-caching.js` sets `Cache-Control: private` for
any member request without ever consulting post visibility. The
`ghost-members-ssr` bypass below is therefore **load-bearing, not
defence-in-depth**.

And a cookie rule alone is not enough anyway: Ghost authenticates members
**from the query string, with no cookie present**. See
[the sharp edge](#the-sharp-edge-cookieless-member-auth) — that section is not
optional reading.

- [The short version](#the-short-version)
- [Why the member-cookie bypass is load-bearing](#why-the-member-cookie-bypass-is-load-bearing)
- [The sharp edge: cookieless member auth](#the-sharp-edge-cookieless-member-auth)
- [Vhost](#vhost)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)
- [Runtime settings / gotchas](#runtime-settings--gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend ghost;      # implies cache_turbo_cache_control honor
```

## Why the member-cookie bypass is load-bearing

| Check | Values |
|---|---|
| URI prefixes | `/ghost/`, `/members/`, `/p/`, `/r/` |
| Query args | `uuid`, `key`, `token`, `gift` |
| Cookie header substrings | `ghost-members-ssr`, `ghost-admin-api-session` |

The question that decides any preset is: *does a logged-in user change the HTML
that a logged-out user would have seen?* For Ghost the answer is **yes, even on a
fully public post** — so the bypass rules below are **load-bearing**, not
defence-in-depth. Do not talk yourself out of them.

It is tempting to reason that a public post is member-invariant, because
`checkPostAccess()` (`services/members/content-gating.js`) *does* return early when
`post.visibility === 'public'` — the post body is never gated for a public post.
**That reasoning is wrong**, and an earlier version of this page made exactly that
mistake:

- `@member` is injected into the template context **unconditionally** whenever a
  member session exists (`update-local-template-options.js`) — it is not gated on
  post visibility. A stock `{{#if @member}}` in the theme (sign-up CTA, "you're
  subscribed" banner, member-only nav) therefore renders **different markup on a
  fully public post**.
- Ghost itself agrees. `frontend-caching.js` sets `Cache-Control: private` for
  **any** request carrying a member session, without ever consulting the post's
  visibility.

So: **bypass on the member cookie, always.** Anonymous readers and crawlers — the
bulk of a blog's traffic — still share one cached entry, which is the entire win.
Members go to origin. That is the trade, and it is a good one.

**`ghost-members-ssr`** is the members session cookie
(`services/members/service.js`), set **only on login**. An anonymous reader gets
**no cookie at all** — which is precisely the property that makes Ghost cacheable
and that Moodle, Nextcloud and the PHP shops lack. The substring also covers
`ghost-members-ssr.sig`, so one entry does both.

## The sharp edge: cookieless member auth

The query-arg rules are **load-bearing, not decoration**. Ghost's
`authMemberByUuid()` (`services/members/middleware.js`) authenticates a member
**purely from the query string** — `?uuid=…&key=…` — with **no cookie involved at
all**. It is how newsletter links identify a reader without a session.

If those args did not bypass, a member-authenticated response would be stored
under a URL that anyone can request, and served to strangers.

```
/my-post?uuid=abc-123&key=deadbeef     <- authenticated. NEVER cache.
/my-post?gift=abc123                   <- UNLOCKED PAID CONTENT. NEVER cache.
```

`token` is the magic-link signin. **`gift` is the one that bites hardest**: a
`?gift=` render serves **unlocked gated content** — a paid post, in full — to a
caller with *no member cookie at all*. Ghost's own cache middleware refuses to
store it (`isGiftRequest()`) for precisely this reason. Cache it and you are
publishing your paid archive.

All four are in the preset. **Do not remove them**, and if you write your own
rules for a Ghost site, do not forget them — this is the one non-obvious
correctness item on the page.

Do not lean on the Cache-Control floor to save you here, either. It normally
would (Ghost sends `private`/`no-store`, and the module refuses to store those,
and never stores a `Set-Cookie` response) — but an operator running
`cache_turbo_cache_control ignore`, which this project's README recommends for
origins that blanket everything with `max-age=0`, has switched that floor **off**.
The arg rules are what hold in that configuration.

## Vhost

Ghost runs as a Node process; this is the nginx in front of it.

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    upstream ghost {
        server 127.0.0.1:2368;
        keepalive 32;
    }

    server {
        listen 443 ssl http2;
        server_name blog.example.com;

        location / {
            cache_turbo               ct;
            cache_turbo_backend       ghost;   # implies cache_control honor

            cache_turbo_key           $scheme$host$uri$is_args$args;
            cache_turbo_valid         300s;    # a blog tolerates a long TTL
            cache_turbo_valid         404 410 1m;
            cache_turbo_preset        balanced;

            proxy_set_header Host              $host;
            proxy_set_header X-Real-IP         $remote_addr;
            proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_http_version 1.1;
            proxy_pass http://ghost;
        }

        # Admin SPA + Admin API. Covered by the preset too; an explicit `off`
        # keeps it out of the cache path entirely.
        location /ghost/ {
            cache_turbo off;
            proxy_set_header Host $host;
            proxy_pass http://ghost;
        }

        # Fingerprinted assets.
        location ~ ^/(assets|content/images)/ {
            cache_turbo off;
            expires 30d;
            access_log off;
            proxy_pass http://ghost;
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
# anonymous reader on a public post: MISS then HIT
curl -sI https://blog.example.com/my-post | grep -i x-cache-turbo
curl -sI https://blog.example.com/my-post | grep -i x-cache-turbo   # HIT

# admin: BYPASS
curl -sI https://blog.example.com/ghost/ | grep -i x-cache-turbo

# a logged-in member: BYPASS
curl -sI -H 'Cookie: ghost-members-ssr=abc123' \
     https://blog.example.com/my-post | grep -i x-cache-turbo       # BYPASS

# THE ONE THAT MATTERS: cookieless member auth via the query string. If this is
# not BYPASS, a member's page can be stored and served to the public.
curl -sI 'https://blog.example.com/my-post?uuid=abc-123&key=deadbeef' \
     | grep -i x-cache-turbo                                        # BYPASS
```

That last check is the one to actually run. The cookie is the obvious rule; the
query string is the one people miss.

## Gotchas

- **`?uuid=` / `?key=` / `?gift=` authenticate or unlock without a cookie.**
  Repeated because it is the only genuinely surprising thing about Ghost. A rule
  set that bypasses only on the cookie is **not** safe — `?gift=` in particular
  hands out full paid content to a caller with no session.
- **A public post is NOT identical for members and strangers.** `@member` is in
  the template context whenever a session exists, regardless of the post's
  visibility, so `{{#if @member}}` changes public-post markup. Bypass on the
  member cookie unconditionally. The cost is only the members' own page views;
  anonymous readers and crawlers are the bulk of the traffic and they all still
  share one cache entry.
- **Gated posts are protected by the origin too.** A `members`/`paid` post served
  to a non-member is a *different, smaller* HTML — but Ghost also marks
  member/admin routes `no-store`, and `cache_turbo_backend` implies
  `cache_control honor`, so those never get stored.
- **Subdirectory installs shift every prefix.** The preset matches `r->uri` from
  the site root, so a Ghost mounted at `/blog/…` needs the rules scoped to that
  `location` (or its own bypass entries). Same caveat as every other preset.
- **`/p/` is unpublished previews.** Never cache them — you would publish a draft.
- **`/r/` is the link-redirect tracker.** Caching it would break click analytics.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached, regardless of preset.

## Runtime settings / gotchas

Ghost is a Node.js (Express) application, not PHP — there is no FPM pool, no
`opcache`, no per-request worker to size. It runs as a single long-lived Node
process, normally installed and supervised by `ghost-cli` as a systemd unit
(`ghost_<instance>.service`) listening on `127.0.0.1:2368`. The tuning surface is
therefore Ghost's own config, not a process manager.

- **`NODE_ENV=production`.** Ghost reads `config.production.json` and enables its
  production code paths (asset minification/fingerprinting, the built-in
  in-memory caches for settings, routing and rendered `{{content}}`) only in the
  production environment. `ghost-cli` sets this for you; a hand-rolled unit that
  forgets it runs Ghost in development mode, which serves un-fingerprinted assets
  and behaves differently under load. This is upstream in-process caching and is
  orthogonal to cache-turbo — it speeds up the origin MISS, it does not make a
  response cacheable at the edge.

- **Ghost's own `Cache-Control` output.** On the public frontend Ghost emits
  `Cache-Control: public, max-age=<caching.frontend.maxAge>`, and
  `caching.frontend.maxAge` **defaults to `0`** — so out of the box every public
  page carries `public, max-age=0`. Admin and members routes are marked
  `private, no-cache, no-store, must-revalidate`. Raising `caching.frontend.maxAge`
  (seconds, in `config.production.json` or via `caching__frontend__maxAge`) is the
  supported way to make Ghost advertise a real freshness window; note that
  `staleWhileRevalidate` / `staleIfError` under `caching.frontend` are
  community-reported as **not fully wired into the emitted header** upstream
  ([TryGhost/Ghost#21886](https://github.com/TryGhost/Ghost/issues/21886)), so do
  not count on them. Because the default is `max-age=0`, this is exactly the
  "origin blankets everything with `max-age=0`" case the README warns about — with
  `cache_turbo_backend ghost` (which implies `cache_control honor`) an unraised
  `maxAge` means the honor floor never lets a page store, and `cache_turbo_valid`
  is what actually gives the blog a usable TTL. Either raise `caching.frontend.maxAge`
  so the two agree, or accept that `cache_turbo_valid` is the source of truth.

- **`X-Cache-Invalidate` is a purge *signal*, and cache-turbo does not act on it.**
  When content changes (publish, edit, unpublish, delete, settings/theme change)
  Ghost emits an `X-Cache-Invalidate` response header naming what became stale —
  in practice `/*` for a site-wide flush, or a specific path list for a narrower
  change. It is a custom, undocumented header that Ghost(Pro)'s own caching layer
  consumes; it is stable but not part of the public API
  ([forum: how is X-Cache-Invalidate used](https://forum.ghost.org/t/how-is-x-cache-invalidate-used/8117)).
  **cache-turbo does not parse or honor it** — there is no directive that turns an
  origin response header into a purge, and none is invented here. The practical
  consequence: after you publish, the old page stays served until its
  `cache_turbo_valid` TTL expires. Keep the blog TTL short enough that stale-after-
  publish is tolerable (the sample uses `cache_turbo_valid 300s`), purge manually
  through the `cache_turbo_admin` endpoint, or run a small sidecar proxy that
  watches for `X-Cache-Invalidate` and calls the admin purge — that logic lives
  outside this module.

- **Members SSR cookie is the login-vary signal — there is nothing else to key
  on.** Ghost does not vary a public post by tier in its HTML output by default
  (member content caching is off unless explicitly enabled), so a member session
  is a binary "bypass" signal, carried entirely by the `ghost-members-ssr` /
  `ghost-members-ssr.sig` cookies (login) and the `?uuid=&key=` / `?token=` /
  `?gift=` query args (cookieless auth). The preset already bypasses on all of
  these; do not try to reproduce Ghost's `req.member` tiering in nginx — the
  `X-Member-Cache-Tier` public-caching path is an advanced, off-by-default Ghost
  feature and outside what this preset targets.

- **`/ghost` admin and `/members` are always origin.** The Admin SPA and Admin API
  (`ghost-admin-api-session` cookie) under `/ghost/` and the members endpoints
  under `/members/` must never be cached; they are in the preset's bypass set and
  the sample vhost also pins `/ghost/` with an explicit `cache_turbo off`. No
  Node-side tuning changes this — these routes are `private, no-store` at the
  origin regardless.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/wordpress.md`](wordpress.md) — the other blog preset
- [`docs/README.md`](README.md) — all presets
