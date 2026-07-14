# Ghost + cache-turbo

Caching a Ghost (5.x/6.x) blog. Ghost is a clean fit: the public blog is a large,
genuinely shared anonymous surface, and — this is the part that makes it work — a
member session does **not** change the HTML of a fully public post. So one bypass
cookie is enough, and anonymous readers all share one cached page.

There is exactly one sharp edge, and it is not the cookie. It is
[the query string](#the-sharp-edge-cookieless-member-auth).

- [The short version](#the-short-version)
- [Why a bypass cookie is enough](#why-a-bypass-cookie-is-enough)
- [The sharp edge: cookieless member auth](#the-sharp-edge-cookieless-member-auth)
- [Vhost](#vhost)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend ghost;      # implies cache_turbo_cache_control honor
```

## Why a bypass cookie is enough

| Check | Values |
|---|---|
| URI prefixes | `/ghost/`, `/members/`, `/p/`, `/r/` |
| Query args | `uuid`, `key`, `token` |
| Cookie substrings | `ghost-members-ssr`, `ghost-admin-api-session` |

The question that decides any preset is: *does a logged-in user change the HTML
that a logged-out user would have seen?* For Ghost, on a **public** post, the
answer is **no** — and that is verifiable in upstream:

- `checkPostAccess()` (`services/members/content-gating.js`) returns `true`
  **immediately** when `post.visibility === 'public'`. The member is never
  consulted; the post's `html` is untouched.
- Content is only stripped when the visitor *lacks* access — i.e. for
  `members`/`paid`/`tiers` posts, which are *supposed* to differ.
- The two things that *do* vary by login state on a public post — Koenig gated
  blocks and the Transistor embed's member-uuid substitution — only fire **when a
  member session exists**. A logged-out stranger always renders the identical
  non-member variant.

So: bypass the members, cache everyone else, and every anonymous reader shares one
HTML. No cache-key variant is needed.

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
```

`token` is the magic-link signin. All three are in the preset. **Do not remove
them**, and if you write your own rules for a Ghost site, do not forget them —
this is the one non-obvious correctness item on the page.

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

- **`?uuid=` / `?key=` authenticate a member without a cookie.** Repeated because
  it is the only genuinely surprising thing about Ghost. A rule set that bypasses
  only on the cookie is **not** safe.
- **A public post is identical for members and strangers**, so bypassing the
  members cookie costs you only the members' own page views — not the shared
  cache. Members are a small fraction of a typical blog's traffic; anonymous
  readers and crawlers are the bulk, and they all share one entry.
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

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/wordpress.md`](wordpress.md) — the other blog preset
- [`docs/README.md`](README.md) — all presets
