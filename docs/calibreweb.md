# Calibre-Web + cache-turbo

_Last researched: 2026-10-06 (janeczku/calibre-web master)._

## Preset

```nginx
cache_turbo         ct;
cache_turbo_backend calibreweb;   # alias: calibre-web
```

<!-- markdownlint-disable MD013 -->

| Check | Values |
| --- | --- |
| Cookie substrings | `session=`, `remember_token=` |
| URI prefixes | `/login`, `/logout`, `/admin`, `/me`, `/download/`, `/show/`, `/send/`, `/ajax/`, `/read/`, `/kobo/`, `/kobo_auth/`, `/remote/login`, `/verify/` |
| Query args | none |

<!-- markdownlint-enable MD013 -->

## Cookies

`session` is the Flask session and `remember_token` the Flask-Login remember
cookie. Both can carry an operator `COOKIE_PREFIX`; the substring match still
covers `cw_session=`. The session cookie is **also** written to guests on search
and guest view settings, so `session=` fails safe: a lost hit, never a leak.

## Conditions for caching guest HTML

1. **Anonymous browsing must be on** (`config_anonbrowse`, default off). With it
   off every page requires a login and nothing is cacheable.
2. **No reverse-proxy header login.** `config_reverse_proxy_login_header_name`
   authenticates by a header with no cookie; the preset cannot see it, so HTML
   from such an install must never be cached. Disable the feature or run with
   `cache_turbo off`.
3. **Key on the language.** Guest HTML language follows `Accept-Language` with no
   `Vary`, so two guests could be served each other's language. Separate the
   header from the URI with a space: nginx rejects a space in the request
   target, so the first space in the key always ends `$request_uri`. Without a
   delimiter `/book/1` with `Accept-Language: en` and `/book/1en` with no header
   produce the same key, and a crafted request could poison the guest page:

```nginx
cache_turbo_key "$scheme$host$request_uri $http_accept_language";
```

   Browsers send many spellings of the same preference, so this splits guest
   entries and lowers the hit rate. That costs hits, not safety; only normalize
   the header with a `map` if the map picks the same language Calibre-Web would.

The application sends no `Cache-Control` on HTML, so guest pages are stored
for `cache_turbo_valid`. Covers and static files go through Flask's
`send_file`, which sends `Cache-Control: no-cache` with an ETag. The module
refuses to store a `no-cache` response under `cache_turbo_cache_control honor`
(implied by the preset), so covers are **not cached** as shipped. To cache them,
give `/cover/`, `/series_cover/` and `/static/` their own location with
`cache_turbo_cache_control ignore;` and a short `cache_turbo_valid`; the cookie
rows still bypass logged-in users there.

## URI rows

Kobo sync carries its token in the path (`/kobo/<token>/`, `/kobo_auth/`) and the
magic-link login uses `/remote/login` and `/verify/<token>`. Downloads, the
reader, send-to-ereader and the AJAX endpoints are per-user. OPDS uses Basic auth
when anonymous browsing is off, which the storage floor refuses to cache.

A `X-Script-Name` prefix needs `cache_turbo_backend_prefix` to match.
