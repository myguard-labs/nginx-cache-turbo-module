# Grav + cache-turbo

_Last researched: 2026-07-26 (Grav 2.0.13, released 2026-07-25)._

**There is no `grav` preset.** Grav's session cookie is never called `grav-site`
on the wire — the name carries a 7-hex digest of the *filesystem install path*,
so it differs on every installation, including between staging and production of
the same site. And Grav initializes the session on every frontend request by
default, so the cookie is set for anonymous first-time visitors regardless.
Neither the name nor the presence is usable as a shippable literal.

There is, however, one genuinely login-only signal: the **admin** session cookie.
This page explains the derivation and then gives a vhost that keys on that and on
the admin route, while explicitly ignoring the frontend session cookie. Same
class of rejection as [`frameworks.md`](frameworks.md).

## Why there is no preset

**1. The cookie name embeds an install-path hash.**
[`SessionServiceProvider.php`](https://github.com/getgrav/grav/blob/develop/system/src/Grav/Common/Service/SessionServiceProvider.php)
computes:

```php
$session_name = hyphenize($config->get('system.session.name', 'grav-site'))
              . '-' . substr(md5(GRAV_ROOT), 0, 7);
```

So the wire name is `grav-site-<7 hex>`, where the hex is `md5(GRAV_ROOT)` — the
absolute filesystem path of the install. `/var/www/grav` and `/srv/grav` produce
different cookies for identical code. A preset cannot ship that literal, and the
stock `grav-site` never appears alone.

When `system.session.split` is true (**the default**), the admin session gets a
distinct name with an `-admin` suffix — that is the one useful signal here.

**2. Anonymous visitors get the frontend cookie.** Grav's shipped `system.yaml`
sets both `session.enabled: true` and `session.initialize: true`, and
[`InitializeProcessor.php`](https://github.com/getgrav/grav/blob/develop/system/src/Grav/Common/Processors/InitializeProcessor.php)
calls `$session->init()` unconditionally on every frontend request. The first hit
by a logged-out stranger returns a `Set-Cookie` for it. Cookie *presence* is
therefore worthless as a login signal on the frontend, exactly as in
[PrestaShop](prestashop.md).

**3. Login state is session content.** Whether a visitor is authenticated is a
`user` object stored *inside* the session data, server-side. nginx sees only an
opaque session id. There is no plaintext login cookie.

<!-- markdownlint-disable MD013 -->

| | What a preset needs | What Grav gives |
| --- | --- | --- |
| Session cookie name | fixed literal | `grav-site-<substr(md5(GRAV_ROOT),0,7)>` — **per-install path hash** |
| Configurable? | ideally not | yes — `system.session.name`, then hyphenized |
| Set for a guest? | no | **yes** — `session.initialize: true` + unconditional `$session->init()` |
| Login discriminator | cookie presence | a `user` object **inside** server-side session data |
| Admin URI | fixed literal | `/admin` is the admin plugin's `route:` — renameable |
| Locale cookie | optional | none — `languages.session_store_active: false`, locale is a URL prefix |

<!-- markdownlint-enable MD013 -->

**4. The admin route is renameable.** `/admin` comes from `route: '/admin'` in
[`grav-plugin-admin/admin.yaml`](https://github.com/getgrav/grav-plugin-admin/blob/develop/admin.yaml)
and operators change it. It is a good default to bypass, not a guarantee.

## Reverse-proxy vhost core

The one thing we *can* key on: with `session.split` at its default, the
`…-admin`-suffixed cookie exists only for admin sessions, which only exist behind
the admin route. Matching it with a regex absorbs the unknown install hash while
staying login-only.

```nginx
http {
    cache_turbo_zone name=ct 256m;

    # Admin session cookie. The install hash is unknown, so match the shape:
    #   <hyphenized session.name>-<7 hex>-admin
    # This IS a login signal (admin sessions only exist behind /admin).
    # The FRONTEND session cookie is deliberately NOT matched -- Grav hands it
    # to every anonymous visitor, so bypassing on it disables the cache.
    map $http_cookie $grav_admin_session {
        default                            0;
        "~*(^|;\s*)grav-site[-\w]*-admin=" 1;
    }

    # Admin route (`route:` in admin.yaml -- edit if you renamed it) and the
    # state-mutating task/nonce parameters.
    map $uri $grav_admin_uri {
        default          0;
        "~*^/admin(/|$)" 1;
    }

    map $arg_task $grav_task {
        default 1;
        ""      0;
    }

    map "$grav_admin_session$grav_admin_uri$grav_task" $grav_private {
        default 1;
        "000"   0;
    }

    upstream grav {
        server unix:/run/php/php8.3-fpm.sock;
    }

    server {
        server_name grav.example.com;
        root /var/www/grav;

        location / {
            cache_turbo               ct;

            # No preset applies -- enable the origin backstop by hand.
            cache_turbo_cache_control honor;

            # bypass skips the lookup; no_store also refuses to save it.
            # Bypass alone would still store the admin page under the shared key.
            cache_turbo_bypass        $grav_private;
            cache_turbo_no_store      $grav_private;

            cache_turbo_key           $scheme$host$uri$is_args$args;
            cache_turbo_valid         120s;
            cache_turbo_valid         404 410 1m;
            cache_turbo_preset        balanced;

            try_files $uri $uri/ /index.php$is_args$args;
        }

        location ~ \.php$ {
            cache_turbo               ct;
            cache_turbo_cache_control honor;
            cache_turbo_bypass        $grav_private;
            cache_turbo_no_store      $grav_private;

            include        fastcgi_params;
            fastcgi_param  SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_pass   grav;
        }

        # Belt and braces. Edit the literal if you renamed the admin route.
        location ^~ /admin {
            cache_turbo off;
            try_files $uri $uri/ /index.php$is_args$args;
        }
    }
}
```

## Verify and caveats

```bash
# Public page: MISS then HIT.
curl -s -o /dev/null -D- https://grav.example.com/blog | grep -i x-cache
curl -s -o /dev/null -D- https://grav.example.com/blog | grep -i x-cache

# Admin route: BYPASS.
curl -s -o /dev/null -D- https://grav.example.com/admin | grep -i x-cache

# Admin session cookie on a public URL: must be BYPASS. Substitute any 7 hex
# chars -- the regex is shape-based, so a fake hash still exercises the rule.
curl -s -o /dev/null -D- -H 'Cookie: grav-site-a1b2c3d-admin=x' \
  https://grav.example.com/blog | grep -i x-cache

# The inverse check: a plain guest must NOT be bypassed, and neither must a
# guest carrying the FRONTEND session cookie -- which every guest gets.
curl -s -o /dev/null -D- -H 'Cookie: grav-site-a1b2c3d=x' \
  https://grav.example.com/blog | grep -i x-cache
# BYPASS here means your regex is too loose and is eating the frontend cookie.
```

- **A renamed `system.session.name` breaks the admin regex.** The map matches
  `grav-site[-\w]*-admin`. If you set `session.name: mysite`, the wire name
  becomes `mysite-<hash>-admin` and the rule never fires. Adjust the pattern to
  your hyphenized name, and re-run the third curl above to prove it matches.
- **`session.split: false` breaks it harder.** With splitting off, the admin
  session shares the frontend cookie name and the `-admin` discriminator does not
  exist. There is then *no* usable cookie signal at all — fall back to the
  `/admin` URI bypass alone and rely on `honor`.
- **A renamed admin route breaks the URI rule.** Edit both the `map` and the
  `location`.
- **Logged-in *frontend* users (the login plugin) are protected only by
  `honor`.** They carry the same cookie as guests. If your theme renders
  per-user content on public pages, verify the origin sends `private`; if it does
  not, those pages are not cacheable.
- **`?task=` and nonce parameters mutate state** and are bypassed above. Grav's
  own nonce parameters ride alongside `task`, so the single check covers them.
- **Language is a URL prefix, not a cookie.** `languages.session_store_active`
  defaults to `false`, so `/en/…` and `/fr/…` are distinct keys via `$uri`
  already. If you enable session-stored language, per-language content collapses
  into one cache entry — do not enable it behind this cache.
- **Grav has its own page cache.** It is a *rendering* cache, not an HTTP cache,
  so it composes fine with cache-turbo (it reduces MISS cost). Leave it on.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached regardless of the above — which is what keeps the anonymous
  first-hit `Set-Cookie` from being captured.

## Origin failure: stale-if-error

By default this module serves a stale cached copy when the origin returns 5xx; nginx turns a refused connection into a 502 and a hung one into a 504, so a dead origin is covered. Once the cached copy's TTL has expired there is no grace window unless one is configured — `cache_turbo_keep_stale <time>` supplies it, and it defaults to `off`. Most CMS/app stacks emit no `stale-if-error` of their own. `cache_turbo_use_stale` selects which statuses count as "down" (default: every 5xx); naming tokens replaces the default rather than extending it. Nothing was ever cached for a URL ⇒ nothing to serve; `error_page 502 503 504 /maintenance.html` is the nicer failure.

```nginx
cache_turbo_keep_stale    2h;
cache_turbo_valid         120s;
```

The copy stays fresh for `120s`; if the origin starts failing after that, the expired copy keeps being served for up to `2h` (`cache_turbo_keep_stale`). Past that window, or with nothing cached at all, `error_page` is the fallback. See the README sections on [which failures count as "the origin is down"](../README.md#which-failures-count-as-the-origin-is-down) and [what outage handling cannot do](../README.md#what-outage-handling-cannot-do).

## See also

- [`docs/README.md`](README.md) — all presets and the apps deliberately rejected
- [`docs/frameworks.md`](frameworks.md) — the same "no preset here either"
  reasoning, plus the 3-curl derivation procedure
- [`docs/prestashop.md`](prestashop.md) — the other app whose session cookie is
  handed to every anonymous guest
