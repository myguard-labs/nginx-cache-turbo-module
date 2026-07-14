# Drupal + cache-turbo

Caching a Drupal 9/10/11 site. The Drupal preset ships **no cookie rule** — but
unlike [phpBB](phpbb.md) and [Joomla](joomla.md), that is mostly fine, because
Drupal defends itself. Read [why](#the-preset-ships-no-cookie-rule--and-thats-ok)
so you know what you are relying on.

- [The short version](#the-short-version)
- [The preset ships no cookie rule — and that's ok](#the-preset-ships-no-cookie-rule--and-thats-ok)
- [Belt and braces](#belt-and-braces)
- [Vhost](#vhost)
- [Vhost + Redis L2](#vhost--redis-l2)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend drupal;      # implies cache_turbo_cache_control honor
```

That is genuinely all most sites need. `cache_turbo_backend` implies
`cache_turbo_cache_control honor`, and Drupal sends `Cache-Control: private,
must-revalidate` on every authenticated response — which `honor` refuses to
store. The preset's URI rules cover the surfaces that are dynamic *before* any
cookie exists.

## The preset ships no cookie rule — and that's ok

| Check | Values |
|---|---|
| URI prefixes | `/user`, `/admin`, `/node/add`, `/system/`, `/core/install.php` |
| Query args | — |
| Cookie substrings | **— (none)** |

Drupal's session cookie is `SESS<32-hex>` — or `SSESS<32-hex>` over TLS — where
the hash is derived per-install from the site's hostname
(`Core/Session/SessionConfiguration.php`). There is no stable suffix, so the only
literal the module could ship is the leading `SESS`.

**And `SESS` is a bad substring to ship.** The preset registry matches substrings
of the whole `Cookie` header, and `SESS` appears inside:

```
PHPSESSID=...      <- every stock PHP app
JSESSIONID=...     <- every stock Java app
```

Shipping it would make cache-turbo bypass on any co-hosted PHP or Java app's
session cookie. That fails *safe* — an unnecessary bypass never leaks anything —
but it would silently zero the hit rate on sites that aren't even Drupal. Not
worth it, so the row is empty.

**What protects logged-in users instead** is the origin. Drupal's
`FinishResponseSubscriber` sets `Cache-Control: private, must-revalidate` on
authenticated responses (and `no-cache, private` when there are no validators),
and cache-turbo's `honor` mode refuses to store a response carrying `private`,
`no-cache` or `no-store`. `cache_turbo_backend` turns `honor` on for you. So the
authenticated page is never stored — not because a cookie rule caught the
request, but because the origin said not to.

There is a second reason the missing cookie rule costs little: **anonymous
readers get no session cookie at all.** Drupal destroys an obsolete session
rather than persisting one, so a plain anonymous visitor is never issued a
`SESS*`. (Which means, unlike phpBB's `_sid`, a `SESS` rule would at least not
have been the "bypasses every guest" trap — the `PHPSESSID` collision is what
rules it out.)

## Belt and braces

If you want the request-side bypass anyway — defence in depth, or because you run
a contrib module that writes to `$_SESSION` and emits pages Drupal marks
cacheable — add your own. Find the cookie name:

```bash
curl -sI -c - https://example.com/user/login | grep -i set-cookie
# Set-Cookie: SSESS9f2a4c1e...=abc123; path=/; secure; HttpOnly
#             ^^^^^^^^^^^^^^^^ this
```

Then either pin the exact name:

```nginx
cache_turbo_bypass $cookie_SSESS9f2a4c1e8b7d6f5a4c3b2a1908070605;
```

…or, better, match the shape without hard-coding a hash that changes if you move
the site to a new hostname:

```nginx
map $http_cookie $drupal_session {
    default                 "";
    "~S?SESS[0-9a-f]{32}="  "1";   # SESS<hash> or SSESS<hash>, Drupal-shaped
}
```

```nginx
cache_turbo_bypass   $drupal_session;
cache_turbo_no_store $drupal_session;
```

That pattern is specific enough not to hit `PHPSESSID` (which has no 32-hex tail),
which is exactly what the shipped preset cannot express with a plain substring.

## Vhost

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    map $http_cookie $drupal_session {
        default                "";
        "~S?SESS[0-9a-f]{32}=" "1";
    }

    server {
        listen 443 ssl http2;
        server_name example.com;
        root /var/www/drupal/web;
        index index.php;

        location / {
            try_files $uri /index.php?$query_string;
        }

        location ~ '\.php$|^/update.php' {
            cache_turbo               ct;
            cache_turbo_backend       drupal;   # implies cache_control honor

            # Optional -- Drupal's own Cache-Control already covers this.
            cache_turbo_bypass        $drupal_session;
            cache_turbo_no_store      $drupal_session;

            cache_turbo_valid         60s;
            cache_turbo_valid         404 410 1m;
            cache_turbo_preset        balanced;

            fastcgi_split_path_info ^(.+?\.php)(|/.*)$;
            include                 fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_pass  unix:/run/php/php-fpm.sock;
        }

        # Aggregated CSS/JS and public files: content-hashed, long-lived.
        location ~ ^/sites/.*/files/ {
            cache_turbo off;
            expires 30d;
            access_log off;
        }

        # Private file downloads are permission-checked per user -- never cache.
        location ^~ /system/files/ {
            cache_turbo off;
        }

        location = /_cache {
            cache_turbo_admin on;
            allow 127.0.0.1;
            deny  all;
        }
    }
}
```

## Vhost + Redis L2

In `http`:

```nginx
cache_turbo_redis redis://10.0.0.5:6379/0 prefix=drupal: timeout=250ms
                  keepalive=32 keepalive_timeout=60s;
```

Drupal's own cache backends (Internal Page Cache, Dynamic Page Cache) live inside
PHP and are a different layer. Leave them on — they make the origin fast, which is
what your cache-turbo misses hit. If you point Drupal's cache at the same Redis,
give cache-turbo a different DB number or `prefix=` so a `?all=1` purge doesn't
clear both.

## Checking it works

```nginx
add_header X-Cache-Turbo $cache_turbo_status always;
```

```bash
# anonymous node: MISS then HIT
curl -sI https://example.com/node/1 | grep -i x-cache-turbo
curl -sI https://example.com/node/1 | grep -i x-cache-turbo   # HIT

# preset URI surfaces: BYPASS
curl -sI https://example.com/user       | grep -i x-cache-turbo
curl -sI https://example.com/admin/config | grep -i x-cache-turbo

# THE ONE THAT MATTERS: a logged-in user must never be served from cache.
# Expect BYPASS if you added the map; if you did not, expect MISS every time
# (Drupal sends Cache-Control: private, so honor mode refuses to STORE it) --
# and crucially, never a HIT.
curl -sI -H 'Cookie: SSESS9f2a...=abc' https://example.com/node/1 \
     | grep -i x-cache-turbo

# Prove the origin really is sending private -- this is your safety net.
curl -sI -H 'Cookie: SSESS9f2a...=abc' https://example.com/node/1 \
     | grep -i cache-control
# Cache-Control: private, must-revalidate     <- if this is missing, ADD THE MAP
```

That last check is the one to actually run. The no-cookie-rule design leans
entirely on Drupal sending `private`. If a contrib module or an aggressive
"performance" setting has stripped it, add the `map` bypass and don't rely on the
origin.

## Gotchas

- **Don't set `cache_turbo_cache_control ignore` on a Drupal site.** It would
  override the `honor` that `cache_turbo_backend` implies, and `honor` is the
  entire reason the preset can get away with no cookie rule. `ignore` + no cookie
  rule = authenticated pages in the cache.
- **`/user` and `/admin` are not reserved words.** They're ordinary Drupal routes,
  which is exactly why `drupal` is **not** in `generic`/`auto` — a non-Drupal site
  may serve `/user` as a perfectly cacheable page. Name the preset explicitly.
- **Contrib modules add their own private surfaces.** Commerce carts, Group,
  Private Message — the preset knows nothing about them. Add a
  `cache_turbo_bypass` for each.
- **`SESS` is not shipped on purpose.** If you're tempted to add
  `cache_turbo_bypass $cookie_SESS...`, use the `map` form above instead — a bare
  `SESS` match will also catch `PHPSESSID` from any other app on the host.
- **`/core/install.php` and `/update.php`** are dynamic; the preset covers the
  former, and the vhost above routes the latter through the same PHP block.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached, regardless of preset. Those floors hold.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/mediawiki.md`](mediawiki.md) — the other preset that leans on origin `Cache-Control`
- [`docs/phpbb.md`](phpbb.md) — a preset with no cookie rule and *no* origin safety net
- [`docs/README.md`](README.md) — all presets
