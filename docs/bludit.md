# Bludit + cache-turbo

_Last researched: 2026-07-26 (Bludit `master`)._

Bludit is another clean fit. Its public bootstrap does not start a PHP session;
the admin bootstrap does.

## Preset

```nginx
cache_turbo         ct;
cache_turbo_backend bludit;
```

<!-- markdownlint-disable MD013 -->

| Check | Values |
| --- | --- |
| Cookie substrings | `BLUDIT-KEY` (also catches `__Secure-BLUDIT-KEY`), `BLUDITREMEMBERUSERNAME=`, `BLUDITREMEMBERTOKEN=` |
| URI prefixes | `/admin`, `/install.php` |
| Query args | — |

<!-- markdownlint-enable MD013 -->

The fixed session name is defined in Bludit's
[`session.class.php`](https://github.com/bludit/bludit/blob/master/bl-kernel/helpers/session.class.php).
Only [`boot/admin.php`](https://github.com/bludit/bludit/blob/master/bl-kernel/boot/admin.php)
starts it. The remember-cookie literals and stock admin slug are defined in
[`boot/variables.php`](https://github.com/bludit/bludit/blob/master/bl-kernel/boot/variables.php).
That source split is why a public page remains cacheable instead of every guest
being bypassed.

## Vhost core

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 128m;

    # /admin is a clean route rewritten to /index.php. Preserve the original
    # request classification across that internal redirect.
    map $request_uri $bludit_private_route {
        default                     0;
        ~^/admin(?:/|\?|$)          1;
    }

    server {
        server_name example.com;
        root /var/www/bludit;

        location / {
            try_files $uri $uri/ /index.php?$args;
        }

        location ~ \.php$ {
            cache_turbo         ct;
            cache_turbo_backend bludit;
            cache_turbo_key     $host$request_uri;
            cache_turbo_valid   300s;
            cache_turbo_preset  balanced;
            cache_turbo_bypass  $bludit_private_route;
            cache_turbo_no_store $bludit_private_route;

            include fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_pass unix:/run/php/php-fpm.sock;
        }
    }
}
```

## Verify and gotchas

```bash
# Public post: MISS then HIT.
curl -s -o /dev/null -D- https://example.com/post | grep -i x-cache
curl -s -o /dev/null -D- https://example.com/post | grep -i x-cache

# Both secure session spelling and admin path: BYPASS.
curl -s -o /dev/null -D- -H 'Cookie: __Secure-BLUDIT-KEY=token' \
  https://example.com/post | grep -i x-cache
curl -s -o /dev/null -D- https://example.com/admin/ | grep -i x-cache
```

- If a fork changes `ADMIN_URI_FILTER`, add that path to the
  `$bludit_private_route` map; current upstream fixes it to `admin`.
- Plugins can start a session or add private public routes. A response that sets
  a cookie is never stored, but subsequent requests need the plugin's stable
  state cookie in a local bypass/no-store rule if it is not one of the names
  above.
- A subdirectory install needs `cache_turbo_backend_prefix /blog/;`.
