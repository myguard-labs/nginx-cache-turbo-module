# Bugzilla + cache-turbo

_Last researched: 2026-07-26 (Bugzilla 5.2 branch)._

Bugzilla has a useful anonymous surface—public bugs, lists, searches and
reports—and fixed member-only login cookies. That makes it one of the few issue
trackers for which a page-cache preset adds value safely.

## Preset rules

```nginx
cache_turbo         ct;
cache_turbo_backend bugzilla;
```

<!-- markdownlint-disable MD013 -->

| Check | Values |
| --- | --- |
| Cookie substrings | `Bugzilla_login=`, `Bugzilla_logincookie=` |
| Query args | `Bugzilla_api_key`, `api_key`, `Bugzilla_api_token`, `Bugzilla_token`, `Bugzilla_login`, `Bugzilla_password`, `Bugzilla_login_token`, `token` |
| URI prefixes | account/login, create/update/request, admin/edit and JSON-RPC/XML-RPC/REST entry points (`/rest` and `/rest.cgi`) |

<!-- markdownlint-enable MD013 -->

The two cookies are read together by
[`Auth/Login/Cookie.pm`](https://github.com/bugzilla/bugzilla/blob/5.2/Bugzilla/Auth/Login/Cookie.pm)
and both are written after every successful login by
[`Auth/Persist/Cookie.pm`](https://github.com/bugzilla/bugzilla/blob/5.2/Bugzilla/Auth/Persist/Cookie.pm).
Remember-me changes expiry, not whether the cookies exist. The
[`APIKey.pm`](https://github.com/bugzilla/bugzilla/blob/5.2/Bugzilla/Auth/Login/APIKey.pm)
login module accepts `Bugzilla_api_key`; the
[`WebService/Util.pm`](https://github.com/bugzilla/bugzilla/blob/5.2/Bugzilla/WebService/Util.pm)
utility also normalizes the short `api_key` spelling. The cookie login module
accepts the legacy API/login tokens. All query-string credential forms
therefore bypass before cookie classification.

`show_bug.cgi`, `buglist.cgi`, `query.cgi`, `report.cgi` and `reports.cgi` are
intentionally not URI-bypassed: they are the public read surface worth caching.
Private bugs are still protected by the login-cookie rule and Bugzilla's own
permissions/cache headers.

## Reverse-proxy core

Put cache-turbo in the nginx location that proxies or FastCGI-wraps Bugzilla;
the origin plumbing varies by deployment:

```nginx
location / {
    cache_turbo         ct;
    cache_turbo_backend bugzilla;
    cache_turbo_key     $scheme$host$uri$is_args$args;
    cache_turbo_valid   30s;
    cache_turbo_preset  conservative;

    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_pass http://bugzilla_origin;
}
```

Trackers change frequently; start at 30 seconds or wire purge to bug changes.
The preset is a privacy classifier, not freshness invalidation.

## Origin failure: stale-if-error

By default this module serves a stale cached copy when the origin returns 5xx; nginx turns a refused connection into a 502 and a hung one into a 504, so a dead origin is covered. Once the cached copy's TTL has expired there is no grace window unless one is configured — `cache_turbo_keep_stale <time>` supplies it, and it defaults to `off`. Most CMS/app stacks emit no `stale-if-error` of their own. `cache_turbo_use_stale` selects which statuses count as "down" (default: every 5xx); naming tokens replaces the default rather than extending it. Nothing was ever cached for a URL ⇒ nothing to serve; `error_page 502 503 504 /maintenance.html` is the nicer failure.

```nginx
cache_turbo_keep_stale   2h;
cache_turbo_valid   30s;
```

The copy stays fresh for `30s`; if the origin starts failing after that, the expired copy keeps being served for up to `2h` (`cache_turbo_keep_stale`). Past that window, or with nothing cached at all, `error_page` is the fallback. See the README sections on [which failures count as "the origin is down"](../README.md#which-failures-count-as-the-origin-is-down) and [what outage handling cannot do](../README.md#what-outage-handling-cannot-do).

## Verify

```bash
# Public bug: MISS then HIT.
curl -s -o /dev/null -D- \
  'https://bugs.example.com/show_bug.cgi?id=1' | grep -i x-cache
curl -s -o /dev/null -D- \
  'https://bugs.example.com/show_bug.cgi?id=1' | grep -i x-cache

# Member and token-authenticated reads: never HIT.
curl -s -o /dev/null -D- -H 'Cookie: Bugzilla_logincookie=token' \
  'https://bugs.example.com/show_bug.cgi?id=1' | grep -i x-cache
curl -s -o /dev/null -D- \
  'https://bugs.example.com/show_bug.cgi?id=1&Bugzilla_api_token=secret' \
  | grep -i x-cache
```

Extensions can add CGI entry points and auth parameters. Audit those locally;
unknown extension routes are outside a core preset.
