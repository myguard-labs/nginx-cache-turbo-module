# Joomla + cache-turbo

Caching a Joomla site. **Read [the warning](#the-preset-is-thin--read-this)
first** — the Joomla preset is deliberately minimal and, unlike the other three,
it does **not** protect logged-in users on its own.

- [The short version](#the-short-version)
- [The preset is thin — read this](#the-preset-is-thin--read-this)
- [Finding your session cookie](#finding-your-session-cookie)
- [Vhost](#vhost)
- [Vhost + Redis L2](#vhost--redis-l2)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend joomla;
cache_turbo_bypass  $cookie_<your_joomla_session_cookie>;   # ← REQUIRED, see below
```

The preset alone skips `/administrator/` and nothing else. The
`cache_turbo_bypass` line is not optional garnish — without it, a logged-in
Joomla user's page can be stored and served to the public.

## The preset is thin — read this

| Check | Values |
|---|---|
| URI prefixes | `/administrator/` |
| Query args | — |
| Cookie substrings | — |

Compare that to the WordPress row (three cookies) and the reason is not
laziness — it's that **Joomla's session cookie has no fixed name.** Joomla derives
it from the site's secret, roughly `md5(md5($secret . 'site'))`, giving a bare
32-hex cookie name with **no stable prefix**:

```
1a79a4d60de6718e8e5b326e338ae533=abc123...      # a real Joomla session cookie
```

(The front end and the administrator get *different* hashes — the `'site'` vs
`'administrator'` component.)

That name is different on every install, so there is no substring the module
could ship that would match your site and not somebody else's. WordPress can ship
`wordpress_logged_in_` because WordPress *prefixes* its hash; Joomla does not —
the whole name is the hash. The preset therefore covers the one thing that *is*
stable — the `/administrator/` path — and leaves the cookie to you.

**Consequence:** `cache_turbo_backend joomla;` on its own gives you an admin-URI
guard and nothing more. A front-end user who logs in gets a session cookie the
module doesn't recognise, so their personalised page is a cache candidate like
any other. You must add the bypass yourself.

The universal floors still apply — a response with `Set-Cookie` is never stored,
and a request with `Authorization` is never cached — so the *login response*
itself won't be captured. But a subsequent page load by an already-logged-in user
carries only the session cookie and no `Set-Cookie`, and that one **will** be
cached unless you bypass it.

## Finding your session cookie

Log in to the front end and look at what Joomla set:

```bash
curl -sI -c - https://example.com/index.php?option=com_users \
  | awk '/Set-Cookie/ {print $2}'
```

Or just read it out of your browser's dev-tools. You're looking for the
32-hex-character cookie name. Then:

```nginx
cache_turbo_bypass $cookie_1a79a4d60de6718e8e5b326e338ae533;
```

If you'd rather not hard-code a hash that changes when the site secret is rotated,
match it with a `map` on the whole `Cookie` header instead:

```nginx
map $http_cookie $joomla_session {
    default              "";
    "~[0-9a-f]{32}="     "1";     # any 32-hex-named cookie = a Joomla session
}
```

```nginx
cache_turbo_bypass $joomla_session;
```

That's blunter (it bypasses on *any* 32-hex cookie, including a guest session
Joomla may have set), which costs you some hit rate but never leaks. On a site
where Joomla issues a session to guests too, prefer the explicit cookie name.

## Vhost

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    map $http_cookie $joomla_session {
        default          "";
        "~[0-9a-f]{32}=" "1";
    }

    server {
        listen 443 ssl http2;
        server_name example.com;
        root /var/www/joomla;
        index index.php;

        location / {
            try_files $uri $uri/ /index.php?$args;
        }

        location ~ \.php$ {
            cache_turbo               ct;
            cache_turbo_backend       joomla;

            # NOT OPTIONAL. The preset ships no cookie rule (see docs).
            cache_turbo_bypass        $joomla_session;
            cache_turbo_no_store      $joomla_session;

            cache_turbo_valid         60s;
            cache_turbo_valid         404 410 1m;
            cache_turbo_preset        balanced;

            include                   fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_pass  unix:/run/php/php-fpm.sock;
        }

        location ~* \.(css|js|png|jpe?g|gif|webp|svg|woff2?)$ {
            cache_turbo off;
            expires 30d;
            access_log off;
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
cache_turbo_redis redis://10.0.0.5:6379/0 prefix=joomla: timeout=250ms
                  keepalive=32 keepalive_timeout=60s;
```

Joomla also has its own object/page caching (Global Configuration → System →
Cache) which is a different layer entirely — it caches Joomla's internal work,
inside PHP. Leave it on; it makes the origin fast, which is what your cache-turbo
misses hit. If you point Joomla's cache at the same Redis, give cache-turbo a
different DB number or `prefix=` so a `?all=1` purge doesn't clear both.

## Checking it works

```nginx
add_header X-Cache-Turbo $cache_turbo_status always;
```

```bash
# anonymous article: MISS then HIT
curl -sI https://example.com/index.php/blog/article | grep -i x-cache-turbo
curl -sI https://example.com/index.php/blog/article | grep -i x-cache-turbo  # HIT

# admin: BYPASS (this is all the preset gives you)
curl -sI https://example.com/administrator/ | grep -i x-cache-turbo

# THE ONE THAT MATTERS: a logged-in front-end user must be BYPASS.
# If this says HIT/MISS, your cache_turbo_bypass is wrong and you are one
# request away from serving a member's page to the public.
curl -sI -H 'Cookie: 1a79a4d60de6718e8e5b326e338ae533=abc' \
     https://example.com/index.php/blog/article | grep -i x-cache-turbo      # BYPASS
```

Run that last check against your **actual** session cookie name before you go
live. It is the whole safety story on Joomla.

## Gotchas

- **The preset does not cover logged-in users.** Said three times because it's the
  one real footgun here. `cache_turbo_backend joomla;` without a
  `cache_turbo_bypass` for your session cookie is not a safe config.
- **Rotating the site secret changes the cookie name** — and silently breaks a
  hard-coded `$cookie_<hash>` bypass. Use the `map` form, or re-check after any
  secret rotation.
- **SEF URLs vary wildly.** With SEF off you get `/index.php?option=com_content&…`;
  with it on, arbitrary paths. The `/administrator/` prefix is stable either way,
  but any custom bypass you write must match your actual URL scheme.
- **Third-party components** (VirtueMart carts, membership extensions) add their
  own private surfaces and their own cookies. The preset knows nothing about them.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached, regardless of preset. Those floors hold.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [README — per-request opt-outs](../README.md#the-cache-key)
- [`docs/README.md`](README.md) — all presets
