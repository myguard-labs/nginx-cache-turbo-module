# Umbraco + cache-turbo

_Last researched: 2026-07-26 (Umbraco CMS `main`, current v17+ token-cookie code)._

Umbraco serves shared published content, but it also has back-office, preview,
member and optional ASP.NET session identities. The stock defaults are
classifiable; customization is the important caveat.

## Preset

```nginx
cache_turbo         ct;
cache_turbo_backend umbraco;
```

<!-- markdownlint-disable MD013 -->

| Check | Values |
| --- | --- |
| URI prefixes | `/umbraco` |
| Cookie substrings | `UMB_UCONTEXT`, `UMB_EXTLOGIN`, `UMB_PREVIEW`, `UMB-WEBSITE-PREVIEW-ACCEPT`, `UMB-XSRF-V`, `UMB_SESSION`, `umbAccessToken`, `umbRefreshToken`, `umbPkceCode`, `.AspNetCore.Identity.Application` |
| Query args | — |

<!-- markdownlint-enable MD013 -->

Current source fixes the preview/XSRF literals in
[`Constants-Web.cs`](https://github.com/umbraco/Umbraco-CMS/blob/main/src/Umbraco.Core/Constants-Web.cs),
defaults back-office auth to `UMB_UCONTEXT` in
[`SecuritySettings.cs`](https://github.com/umbraco/Umbraco-CMS/blob/main/src/Umbraco.Core/Configuration/Models/SecuritySettings.cs),
and makes v17+ back-office token cookies from the stable `umbAccessToken`,
`umbRefreshToken` and `umbPkceCode` bases. A configurable site suffix and
`__Host-` prefix do not defeat substring matching.
`UMB_EXTLOGIN` and `UMB_SESSION` are conservative legacy/optional compatibility
guards, not claims about the current default authentication scheme.

Published-page output caching in current Umbraco independently refuses preview
and authenticated requests in
[`DefaultWebsiteOutputCacheRequestFilter.cs`](https://github.com/umbraco/Umbraco-CMS/blob/main/src/Umbraco.Web.Website/Caching/DefaultWebsiteOutputCacheRequestFilter.cs),
and refuses responses with `Set-Cookie`/`no-store` in
[`WebsiteOutputCachePolicy.cs`](https://github.com/umbraco/Umbraco-CMS/blob/main/src/Umbraco.Web.Website/Caching/WebsiteOutputCachePolicy.cs).
cache-turbo follows the same request split and honors the response split.

## Reverse-proxy vhost core

```nginx
http {
    cache_turbo_zone name=ct 256m;

    upstream umbraco {
        server 127.0.0.1:5000;
        keepalive 32;
    }

    server {
        server_name example.com;

        location / {
            cache_turbo         ct;
            cache_turbo_backend umbraco;
            cache_turbo_key     $scheme$host$uri$is_args$args;
            cache_turbo_valid   60s;
            cache_turbo_preset  conservative;

            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_http_version 1.1;
            proxy_pass http://umbraco;
        }

        location /umbraco/ {
            cache_turbo off;
            proxy_pass http://umbraco;
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
# Published content: MISS then HIT when origin headers permit it.
curl -s -o /dev/null -D- https://example.com/news | grep -i x-cache
curl -s -o /dev/null -D- https://example.com/news | grep -i x-cache

# Member and preview: never HIT.
curl -s -o /dev/null -D- \
  -H 'Cookie: .AspNetCore.Identity.Application=token' \
  https://example.com/news | grep -i x-cache
curl -s -o /dev/null -D- -H 'Cookie: UMB_PREVIEW=token' \
  https://example.com/news | grep -i x-cache
```

- `SecuritySettings.AuthCookieName` and ASP.NET Identity's application-cookie
  name are configurable. If either differs, add the actual cookie with both
  `cache_turbo_bypass` and `cache_turbo_no_store`. A renamed member cookie is an
  unsafe missed match, not merely a hit-rate issue.
- Custom authentication schemes, member areas and controllers are application
  code. The preset covers Umbraco defaults, not arbitrary ASP.NET extensions.
- Keep `honor` mode. Modern Umbraco's own output-cache eligibility, antiforgery
  `no-store` and `Set-Cookie` decisions are valuable defence in depth.
- A subdirectory install needs `cache_turbo_backend_prefix /site/;`.
