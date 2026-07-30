# Wiki.js + cache-turbo

_Last researched: 2026-07-26 (Wiki.js 2.5 `main`, v2.5.314 current)._

Wiki.js published pages can be shared for logged-out visitors. Authentication
uses a fixed JWT cookie, while the globally installed Express session is not
saved for untouched guests. The preset leaves arbitrary published page paths
cacheable and removes the identity, editor, source and API surfaces.

## Preset

```nginx
cache_turbo         ct;
cache_turbo_backend wikijs;
```

<!-- markdownlint-disable MD013 -->

| Check | Values |
| --- | --- |
| Cookie substrings | `jwt=`, `connect.sid=`, `loginRedirect=` |
| URI prefixes | `/a`, `/d`, `/e`, `/h`, `/p`, `/s`, `/u`, `/login`, `/logout`, `/register`, `/verify`, `/login-reset`, `/graphql`, `/graphql-subscriptions` |
| Query args | — |

<!-- markdownlint-enable MD013 -->

Wiki.js configures `express-session` with `saveUninitialized: false` in
[`server/master.js`](https://github.com/requarks/wiki/blob/main/server/master.js),
so merely viewing a public page does not create the default `connect.sid`
cookie. Its authentication middleware extracts identity from the
`Authorization` header or fixed `jwt` cookie in
[`server/helpers/security.js`](https://github.com/requarks/wiki/blob/main/server/helpers/security.js).
cache-turbo's generic `Authorization` floor covers the header form; this preset
covers the cookie form and OAuth sessions.

The controller routes and ACL checks are visible in
[`server/controllers/common.js`](https://github.com/requarks/wiki/blob/main/server/controllers/common.js).
Published page HTML includes the effective permissions and navigation for the
current group. All logged-in group variants carry `jwt` and bypass; logged-out
visitors share the single guest-group representation. Wiki.js' latest listed
release is v2.5.314; its own requirements page still describes 2.x while noting
that a future 3.x changes platform support.

## Reverse-proxy vhost core

```nginx
http {
    cache_turbo_zone name=ct 256m;

    upstream wikijs {
        server 127.0.0.1:3000;
        keepalive 32;
    }

    server {
        server_name wiki.example.com;

        location / {
            cache_turbo         ct;
            cache_turbo_backend wikijs;
            cache_turbo_key     $scheme$host$uri$is_args$args;
            cache_turbo_valid   60s;
            cache_turbo_preset  conservative;

            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_http_version 1.1;
            proxy_pass http://wikijs;
        }
    }
}
```

## Origin failure: stale-if-error

By default this module serves a stale cached copy when the origin returns 5xx; nginx turns a refused connection into a 502 and a hung one into a 504, so a dead origin is covered. Once the cached copy's TTL has expired there is no grace window unless one is configured — `cache_turbo_keep_stale <time>` supplies it, and it defaults to `off`. Most CMS/app stacks emit no `stale-if-error` of their own. `cache_turbo_use_stale` selects which statuses count as "down" (default: every 5xx); naming tokens replaces the default rather than extending it. Nothing was ever cached for a URL ⇒ nothing to serve; `error_page 502 503 504 /maintenance.html` is the nicer failure.

```nginx
cache_turbo_keep_stale   2h;
cache_turbo_valid   60s;
```

The copy stays fresh for `60s`; if the origin starts failing after that, the expired copy keeps being served for up to `2h` (`cache_turbo_keep_stale`). Past that window, or with nothing cached at all, `error_page` is the fallback. See the README sections on [which failures count as "the origin is down"](../README.md#which-failures-count-as-the-origin-is-down) and [what outage handling cannot do](../README.md#what-outage-handling-cannot-do).

## Verify and caveats

```bash
# Published page: MISS then HIT when origin headers permit it.
curl -s -o /dev/null -D- https://wiki.example.com/guide | grep -i x-cache
curl -s -o /dev/null -D- https://wiki.example.com/guide | grep -i x-cache

# Authenticated, editor and GraphQL requests: never HIT.
curl -s -o /dev/null -D- -H 'Cookie: jwt=token' \
  https://wiki.example.com/guide | grep -i x-cache
curl -s -o /dev/null -D- https://wiki.example.com/e/guide | grep -i x-cache
curl -s -o /dev/null -D- https://wiki.example.com/graphql | grep -i x-cache
```

- This preset targets Wiki.js 2.x. Re-audit cookie and route literals before
  using it with the forthcoming 3.x architecture.
- Keep `cache_turbo_cache_control honor`. Token renewal explicitly emits
  `Cache-Control: no-store`, and the module's `Set-Cookie` floor is defence in
  depth for login redirects and third-party authentication strategies.
- Custom middleware, proxy authentication or extensions can add identity
  channels and private routes. Add matching bypass and no-store rules; a fixed
  app preset cannot infer custom code.
- Wiki.js' official troubleshooting guide says subfolder installs are not
  supported. Put it on a host/subdomain instead of relying on
  `cache_turbo_backend_prefix` for a production Wiki.js mount.
