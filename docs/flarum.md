# Flarum + cache-turbo

_Last researched: 2026-07-26 (flarum/framework `main` at 2.0.0-rc.5; identical
cookie mechanics in the 1.8.x stable line)._

Flarum is a single-page forum whose discussion URLs are perfectly cacheable for
logged-out visitors. The one thing you must get right is **which** cookie means
"logged in" — Flarum issues its session cookie to everybody, including anonymous
guests, so the obvious rule is the wrong one.

## Preset

```nginx
cache_turbo         ct;
cache_turbo_backend flarum;
```

<!-- markdownlint-disable MD013 -->

| Check | Values |
| --- | --- |
| Cookie substrings | `flarum_remember=` |
| URI prefixes | `/admin`, `/api`, `/login`, `/logout`, `/global-logout`, `/register`, `/reset`, `/confirm`, `/settings`, `/notifications` |
| Query args | — |

<!-- markdownlint-enable MD013 -->

## `flarum_session` is not a login signal

[`Http/Middleware/StartSession.php`](https://github.com/flarum/framework/blob/main/framework/core/src/Http/Middleware/StartSession.php)
applies the session cookie unconditionally, on every response, before any
authentication check:

```php
$session->start();
$response = $handler->handle($request);
$session->save();
$response = $this->withCsrfTokenHeader($response, $session);
return $this->withSessionCookie($response, $session);
```

So an anonymous visitor's very first request comes back with
`Set-Cookie: flarum_session=…`, and every subsequent request carries it. **A
preset row matching `flarum_session` would fire on essentially 100% of traffic
and silently disable the cache** — the responses would still be correct, so no
correctness test would notice; you would simply observe that cache-turbo "isn't
very fast". The preset therefore matches only `flarum_remember`, written solely
by
[`Http/Rememberer.php`](https://github.com/flarum/framework/blob/main/framework/core/src/Http/Rememberer.php)
(`COOKIE_NAME = 'remember'`) at login.

Both names carry the prefix from
[`Http/CookieFactory.php`](https://github.com/flarum/framework/blob/main/framework/core/src/Http/CookieFactory.php)
— `$prefix = $config['cookie.name'] ?? 'flarum'`, and `getName()` returns
`"{$prefix}_{$name}"` — so the wire names are exactly `flarum_session` and
`flarum_remember` at stock configuration.

## Known gap: a login without "remember me"

**This preset does not fully protect a user who logs in with "remember me"
unchecked.** Such a session carries only `flarum_session`, whose guest and
member forms are distinguishable solely by the session id's server-side mapping
to a stored access token (`SessionAuthenticator`). nginx cannot tell them apart,
so the cookie tier is blind to that user.

`/api` in the URI tier contains most of the exposure — Flarum's frontend is a
SPA that fetches discussion content through it, so the personalised payload is
never cached. The residual risk is the server-rendered HTML shell at plain
discussion URLs.

If your forum needs that closed, add a value-aware rule in front of the preset:

```nginx
# Treat ANY flarum_session as private, at the cost of caching only
# genuinely cookie-less visitors (first-time and crawler traffic).
map $http_cookie $flarum_has_session {
    default                  0;
    "~*(^|;\s*)flarum_session=" 1;
}

location / {
    cache_turbo          ct;
    cache_turbo_backend  flarum;
    cache_turbo_bypass   $flarum_has_session;
    cache_turbo_no_store $flarum_has_session;
    # ...
}
```

That is a deliberate hit-rate-for-safety trade and is **not** the preset default,
because on a busy public forum it reduces the cacheable population to first-time
visitors. Choose it knowingly.

## Reverse-proxy vhost core

```nginx
http {
    cache_turbo_zone name=ct 256m;

    upstream flarum {
        server 127.0.0.1:8888;
        keepalive 32;
    }

    server {
        server_name forum.example.com;

        location / {
            cache_turbo         ct;
            cache_turbo_backend flarum;
            cache_turbo_key     $scheme$host$uri$is_args$args;
            cache_turbo_valid   60s;
            cache_turbo_preset  conservative;

            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_http_version 1.1;
            proxy_pass http://flarum;
        }
    }
}
```

## Verify and caveats

```bash
# Public discussion: MISS then HIT.
curl -s -o /dev/null -D- https://forum.example.com/d/1-welcome | grep -i x-cache
curl -s -o /dev/null -D- https://forum.example.com/d/1-welcome | grep -i x-cache

# A guest's session cookie must NOT prevent caching.
curl -s -o /dev/null -D- -H 'Cookie: flarum_session=guestid' \
  https://forum.example.com/d/1-welcome | grep -i x-cache   # expect HIT

# Remembered login, admin and API: never HIT.
curl -s -o /dev/null -D- -H 'Cookie: flarum_remember=tok' \
  https://forum.example.com/d/1-welcome | grep -i x-cache
curl -s -o /dev/null -D- https://forum.example.com/api/discussions | grep -i x-cache
curl -s -o /dev/null -D- https://forum.example.com/admin | grep -i x-cache
```

- **Renaming breaks this preset silently and unsafely.** `cookie.name` in
  `config.php` changes both cookie names, and `paths.admin` / `paths.api` rename
  those routes. A renamed prefix means `flarum_remember` stops matching and
  logged-in users are served cached guest pages; a renamed `paths.admin` leaves
  the admin panel cacheable. If you have overridden either, add explicit
  `cache_turbo_bypass` + `cache_turbo_no_store` rules for the new names.
- Mounted under a subdirectory, add `cache_turbo_backend_prefix /forum/;` — the
  URI rows anchor at byte 0.
- Keep `cache_turbo_cache_control honor`; the `Set-Cookie` floor is defence in
  depth for the login flow.
- Extensions can add private routes and identity channels. A fixed preset cannot
  infer extension code — add matching rules yourself.

## See also

- [README.md](README.md) — the docs index and the full preset table.
- [nodebb.md](nodebb.md) — the same guest-issued-cookie problem, but with **no**
  login-only cookie at all, which is why NodeBB gets no preset.
- [redmine.md](redmine.md), [opencart.md](opencart.md) — shipped in the same pass.
