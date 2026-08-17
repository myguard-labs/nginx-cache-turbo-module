# SPIP + cache-turbo

_Last researched: 2026-07-26 (SPIP `spip/ecrire` 5.x)._

SPIP already has an internal template cache, but an nginx page cache still
removes PHP/bootstrap work on anonymous reads. The preset is deliberately
conservative about presentation cookies.

## Preset rules

```nginx
cache_turbo         ct;
cache_turbo_backend spip;
```

<!-- markdownlint-disable MD013 -->

| Check | Values |
| --- | --- |
| Cookie-name suffix, non-empty | `_session`, `_admin`, `_lang`, `_lang_ecrire`, `_accepte_ajax` |
| URI prefixes | `/ecrire` |
| Query args, any value | `action`, `var_mode` |

<!-- markdownlint-enable MD013 -->

SPIP's default `$cookie_prefix` is `spip` in
[`bootstrap/config/globals.php`](https://git.spip.net/spip/ecrire/-/blob/5.x/bootstrap/config/globals.php),
while [`inc/cookie.php`](https://git.spip.net/spip/ecrire/-/blob/5.x/inc/cookie.php)
rewrites every `spip_*` wire name when an operator changes it. Matching the
invariant suffix keeps a renamed install protected. The session, admin and
language writers are visible in
[`bootstrap/inc/auth.php`](https://git.spip.net/spip/ecrire/-/blob/5.x/bootstrap/inc/auth.php),
[`action/cookie.php`](https://git.spip.net/spip/ecrire/-/blob/5.x/action/cookie.php)
and [`action/converser.php`](https://git.spip.net/spip/ecrire/-/blob/5.x/action/converser.php).

Language and Ajax-capability cookies are not authentication, but they can change
the rendered response. They bypass rather than enter the key: that costs a miss
for those visitors and cannot let a client steer a shared cache bucket.
`var_mode` selects recalculate, preview and debug modes in
[`bootstrap/inc/initialization.php`](https://git.spip.net/spip/ecrire/-/blob/5.x/bootstrap/inc/initialization.php);
`action` dispatches action handlers. Both bypass even without a cookie.

## Vhost core

```nginx
http {
    cache_turbo_zone name=ct 256m;

    server {
        server_name example.com;
        root /var/www/spip;

        location / {
            try_files $uri $uri/ /spip.php?$args;
        }

        location ~ \.php$ {
            cache_turbo         ct;
            cache_turbo_backend spip;
            cache_turbo_key     $host$request_uri;
            cache_turbo_valid   120s;
            cache_turbo_preset  balanced;

            include fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_pass unix:/run/php/php-fpm.sock;
        }
    }
}
```

If `_DIR_RESTREINT_ABS` moves the private area away from `/ecrire`, add the
actual URI. If the whole site is mounted below `/site/`, use
`cache_turbo_backend_prefix /site/;`.

## Origin failure: stale-if-error

By default this module can serve a stale cached copy when the origin returns 5xx; nginx turns a refused connection into a 502 and a hung one into a 504, so a dead origin is covered. If the response supplies no `stale-if-error`, `cache_turbo_keep_stale` provides the fallback window — it defaults to `24h`, and `cache_turbo_keep_stale off` removes that fallback. An honored response `stale-if-error` takes precedence, while an honored `must-revalidate` forbids stale serving. `cache_turbo_use_stale` selects which statuses count as "down" (default: every 5xx); listing any tokens replaces the default rather than extending it. Nothing was ever cached for a URL ⇒ nothing to serve; `error_page 502 503 504 /maintenance.html` is the final fallback.

```nginx
cache_turbo_keep_stale   2h;
cache_turbo_valid   120s;
```

The copy stays fresh for `120s`; if the origin starts failing after that, the expired copy keeps being served for up to `2h` (`cache_turbo_keep_stale`). Past that window, or with nothing cached at all, `error_page` is the fallback. See the README sections on [which failures count as "the origin is down"](../README.md#which-failures-count-as-the-origin-is-down) and [what outage handling cannot do](../README.md#what-outage-handling-cannot-do).

## Verify

```bash
# Shared page: MISS then HIT.
curl -s -o /dev/null -D- https://example.com/spip.php?page=sommaire | grep -i x-cache
curl -s -o /dev/null -D- https://example.com/spip.php?page=sommaire | grep -i x-cache

# Custom prefix proves suffix matching; preview proves query classification.
curl -s -o /dev/null -D- -H 'Cookie: ACME_session=token' \
  https://example.com/spip.php?page=sommaire | grep -i x-cache
curl -s -o /dev/null -D- \
  'https://example.com/spip.php?page=sommaire&var_mode=preview' | grep -i x-cache
```

Use a short TTL or purge when publishing. SPIP's internal invalidation cannot
directly invalidate an independent nginx entry.
