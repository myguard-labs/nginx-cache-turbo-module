# Redmine + cache-turbo

_Last researched: 2026-07-26 (Redmine 7.0.0 current; mechanics unchanged since 5.x)._

Redmine is the cleanest of the trackers to cache: its session cookie name is a
hardcoded string literal rather than a config-derived or hashed value, so the
preset can classify on it directly. The interesting part of this preset is not
the cookie tier but the **query-argument tier** — Redmine authenticates via
`?key=` with no cookie at all, and a cookie-only rule would cache private
content under the public cache key.

## Preset

```nginx
cache_turbo         ct;
cache_turbo_backend redmine;
```

<!-- markdownlint-disable MD013 -->

| Check | Values |
| --- | --- |
| Cookie substrings | `_redmine_session=`, `autologin=` |
| URI prefixes | `/admin`, `/my`, `/login`, `/logout`, `/account`, `/settings`, `/enumerations`, `/roles`, `/trackers`, `/custom_fields`, `/auth_sources`, `/mail_handler` |
| Query args | `key` |

<!-- markdownlint-enable MD013 -->

`_redmine_session` is a literal in
[`config/application.rb`](https://github.com/redmine/redmine/blob/master/config/application.rb):

```ruby
config.session_store(
  :cookie_store,
  :key => '_redmine_session',
  :path => config.relative_url_root || '/',
  :same_site => :lax
)
```

It is not derived from configuration, which is what makes a fixed preset viable
here — most of the applications researched alongside Redmine derive their cookie
name from an install path, app id, or version hash. `autologin` is the
remember-me cookie; its name *is* settable
(`Redmine::Configuration['autologin_cookie_name']` in
[`app/controllers/application_controller.rb`](https://github.com/redmine/redmine/blob/master/app/controllers/application_controller.rb))
but falls back to the literal `autologin`, so a renamed one degrades to "the
active session cookie still catches the login" rather than to nothing.

## `?key=` is not optional

`application_controller.rb` accepts `key` on two separate paths, **neither of
which starts a session**:

- **Atom key** — `params[:format] == 'atom' && params[:key]` →
  `User.find_by_atom_key(params[:key])`
- **API key** — `api_key_from_request` when `Setting.rest_api_enabled?`

So `GET /issues?key=<atom key>&format=atom` returns a private, per-user issue
list carrying **no cookies whatsoever**. Without the arg rule, cache-turbo would
store that response under a key indistinguishable from the anonymous one and
serve one user's private tracker to every subsequent visitor. This is the same
class of hole the `ghost` preset's `?uuid=` / `?key=` / `?gift=` rows close.

`Authorization` (OAuth via Doorkeeper, and HTTP Basic) is covered by
cache-turbo's generic header floor and needs no preset row.

## What is deliberately NOT bypassed

The URI tier does **not** list `/projects`, `/issues`, `/news`, `/wiki` or
`/repository`. On an open tracker those are the main public content and the
entire reason to put a cache in front of Redmine. Whether a given project is
public is a per-project ACL that nginx cannot see — the **cookie rule** is what
protects a logged-in user's view of them, and the `key` rule is what protects
the cookieless API view. A preset that bypassed those paths would be safe and
pointless.

## Reverse-proxy vhost core

```nginx
http {
    cache_turbo_zone name=ct 256m;

    upstream redmine {
        server 127.0.0.1:3000;
        keepalive 32;
    }

    server {
        server_name tracker.example.com;

        location / {
            cache_turbo         ct;
            cache_turbo_backend redmine;
            cache_turbo_key     $scheme$host$uri$is_args$args;
            cache_turbo_valid   60s;
            cache_turbo_preset  conservative;

            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_http_version 1.1;
            proxy_pass http://redmine;
        }
    }
}
```

Mounted under a subdirectory (`RedmineApp` at `/redmine`), add
`cache_turbo_backend_prefix /redmine/;` — the preset's URI rules are anchored at
byte 0 and will not otherwise match.

## Verify and caveats

```bash
# Public issue list: MISS then HIT.
curl -s -o /dev/null -D- https://tracker.example.com/issues | grep -i x-cache
curl -s -o /dev/null -D- https://tracker.example.com/issues | grep -i x-cache

# Atom/API key: never HIT, even with no cookie.
curl -s -o /dev/null -D- 'https://tracker.example.com/issues?key=DEADBEEF&format=atom' \
  | grep -i x-cache

# Logged-in and admin: never HIT.
curl -s -o /dev/null -D- -H 'Cookie: _redmine_session=abc' \
  https://tracker.example.com/issues | grep -i x-cache
curl -s -o /dev/null -D- https://tracker.example.com/admin | grep -i x-cache
```

- **A private tracker gains nothing from this preset.** If every project is
  behind a login, essentially all traffic carries `_redmine_session` and
  bypasses. cache-turbo is worth deploying in front of Redmine when a meaningful
  share of traffic is anonymous.
- Redmine's session is a Rails **cookie_store**, so the session lives in the
  cookie itself. Whether a genuinely stateless anonymous `GET` emits
  `Set-Cookie` depends on runtime CSRF/flash behaviour and is not statically
  determinable; if your instance sets it on every response, anonymous requests
  will bypass too and the cache will be less useful than expected. Confirm with
  `curl -sI https://tracker.example.com/issues | grep -i set-cookie` before
  sizing the zone.
- `autologin_cookie_name`, `autologin_cookie_path` and `autologin_cookie_secure`
  are all settable in `config/configuration.yml`. A renamed autologin cookie is
  not matched; add it with `cache_turbo_bypass` if you changed it.
- Keep `cache_turbo_cache_control honor`. Redmine emits `no-store` on the
  surfaces that need it, and the `Set-Cookie` floor is defence in depth.
- Plugins can add private routes under paths this preset does not know. Add
  matching `cache_turbo_bypass` **and** `cache_turbo_no_store` rules; a fixed
  preset cannot infer plugin code.

## Origin failure: stale-if-error

By default this module serves a stale cached copy when the origin returns 5xx; nginx turns a refused connection into a 502 and a hung one into a 504, so a dead origin is covered. Once the cached copy's TTL has expired there is no grace window unless one is configured — `cache_turbo_keep_stale <time>` supplies it, and it defaults to `off`. Most CMS/app stacks emit no `stale-if-error` of their own. `cache_turbo_use_stale` selects which statuses count as "down" (default: every 5xx); naming tokens replaces the default rather than extending it. Nothing was ever cached for a URL ⇒ nothing to serve; `error_page 502 503 504 /maintenance.html` is the nicer failure.

```nginx
cache_turbo_keep_stale   2h;
cache_turbo_valid   60s;
```

The copy stays fresh for `60s`; if the origin starts failing after that, the expired copy keeps being served for up to `2h` (`cache_turbo_keep_stale`). Past that window, or with nothing cached at all, `error_page` is the fallback. See the README sections on [which failures count as "the origin is down"](../README.md#which-failures-count-as-the-origin-is-down) and [what outage handling cannot do](../README.md#what-outage-handling-cannot-do).

## See also

- [README.md](README.md) — the docs index and the full preset table.
- [flarum.md](flarum.md), [opencart.md](opencart.md) — shipped in the same pass;
  both exist mainly to document a guest-issued session cookie.
