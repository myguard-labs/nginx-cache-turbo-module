# Plone + cache-turbo

_Last researched: 2026-07-26 (Products.CMFPlone `master`)._

Plone has a substantial anonymous publishing surface and a mature cache-header
ecosystem. cache-turbo should complement those headers, not override them.

## Preset

```nginx
cache_turbo         ct;
cache_turbo_backend plone;   # implies cache_turbo_cache_control honor
```

<!-- markdownlint-disable MD013 -->

| Check | Values |
| --- | --- |
| Cookie substrings | `__ac=`, `_ZopeId=`, `statusmessages=`, `I18N_LANGUAGE=` |
| URI prefixes | `/login`, `/logout`, `/register`, `/passwordreset`, `/mail_password`, `/manage`, `/@@login` |
| Query args | — |

<!-- markdownlint-enable MD013 -->

Plone's current cookie-auth tests pin `__ac` as the successful-login cookie in
[`testCookieAuth.py`](https://github.com/plone/Products.CMFPlone/blob/master/src/Products/CMFPlone/tests/testCookieAuth.py),
and the login view marks its response `private` in
[`browser/login/login.py`](https://github.com/plone/Products.CMFPlone/blob/master/src/Products/CMFPlone/browser/login/login.py).
The other cookies cover Zope browser sessions, flash/status messages and an
explicit language override. `Products.statusmessages` stores its messages in the
fixed `statusmessages` cookie; `Products.Sessions` defaults the browser ID to
`_ZopeId`.

Why bypass language instead of keying it? Plone can also negotiate language from
host/path and `Accept-Language`; folding only one cookie into a cache key would
pretend to model the whole policy. A conservative bypass is safer and affects
only visitors carrying an override.

## Reverse-proxy vhost core

```nginx
http {
    cache_turbo_zone name=ct 256m;

    upstream plone {
        server 127.0.0.1:8080;
        keepalive 16;
    }

    server {
        server_name example.com;

        location / {
            cache_turbo         ct;
            cache_turbo_backend plone;
            cache_turbo_key     $scheme$host$uri$is_args$args;
            cache_turbo_valid   60s;
            cache_turbo_preset  conservative;

            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_http_version 1.1;
            proxy_pass http://plone;
        }
    }
}
```

If Plone is published under `/site/`, add
`cache_turbo_backend_prefix /site/;` so root login/manage rules rebase.

## Origin failure: stale-if-error

By default this module serves a stale cached copy when the origin returns 5xx; nginx turns a refused connection into a 502 and a hung one into a 504, so a dead origin is covered. Once the cached copy's TTL has expired there is no grace window unless one is configured — `cache_turbo_keep_stale <time>` supplies it, and it defaults to `off`. Most CMS/app stacks emit no `stale-if-error` of their own. `cache_turbo_use_stale` selects which statuses count as "down" (default: every 5xx); naming tokens replaces the default rather than extending it. Nothing was ever cached for a URL ⇒ nothing to serve; `error_page 502 503 504 /maintenance.html` is the nicer failure.

```nginx
cache_turbo_keep_stale   2h;
cache_turbo_valid   60s;
```

The copy stays fresh for `60s`; if the origin starts failing after that, the expired copy keeps being served for up to `2h` (`cache_turbo_keep_stale`). Past that window, or with nothing cached at all, `error_page` is the fallback. See the README sections on [which failures count as "the origin is down"](../README.md#which-failures-count-as-the-origin-is-down) and [what outage handling cannot do](../README.md#what-outage-handling-cannot-do).

## Verify and caveats

```bash
# Published page: MISS then HIT only if Plone's headers permit it.
curl -s -o /dev/null -D- https://example.com/news | grep -Ei 'x-cache|cache-control'
curl -s -o /dev/null -D- https://example.com/news | grep -Ei 'x-cache|cache-control'

# Auth/status state: never HIT.
curl -s -o /dev/null -D- -H 'Cookie: __ac=token' \
  https://example.com/news | grep -i x-cache
curl -s -o /dev/null -D- -H 'Cookie: statusmessages=encoded' \
  https://example.com/news | grep -i x-cache
```

- Do not set `cache_turbo_cache_control ignore`. Plone and
  `plone.app.caching` know more about workflow state, permissions and purge than
  a fixed preset does.
- A Zope BrowserIdManager can rename `_ZopeId`. If yours does, add the actual
  cookie to `cache_turbo_bypass` **and** `cache_turbo_no_store`.
- Add-ons can introduce anonymous personalization and traversal views. Logged-in
  traversal views such as `folder/@@edit` are caught by `__ac`; an add-on that
  authenticates some other way needs its own rule.
