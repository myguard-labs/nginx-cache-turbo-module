# Textpattern + cache-turbo

_Last researched: 2026-07-26 (Textpattern `dev` branch)._

Textpattern is a strong page-cache fit: public articles are shared HTML, while
every successful login produces fixed-name cookies that the proxy can see.

## Preset

```nginx
cache_turbo         ct;
cache_turbo_backend textpattern;   # implies cache_turbo_cache_control honor
```

| Check | Values |
| --- | --- |
| Cookie substrings | `txp_login_public=`, `txp_login=` |
| URI prefixes | `/textpattern` |
| Query args | — |

The cookie choices come from Textpattern's current
[`txp_auth.php`](https://github.com/textpattern/textpattern/blob/dev/textpattern/include/txp_auth.php):
the admin cookie and public-path cookie are both written on successful login and
cleared on logout. Public rendering checks `txp_login_public` in
[`txplib_misc.php`](https://github.com/textpattern/textpattern/blob/dev/textpattern/lib/txplib_misc.php),
so it is the load-bearing frontend rule. Anonymous article reads do not receive
either cookie.

`/textpattern` is the stock admin directory. Textpattern allows that directory
to be renamed. If you renamed it to `/control`, add the real path:

```nginx
cache_turbo_bypass_uri /control;
```

The login cookie still protects a signed-in editor on public pages; the extra
URI rule protects login and admin requests before a cookie exists.

## Vhost core

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    server {
        server_name example.com;
        root /var/www/textpattern;

        location / {
            try_files $uri $uri/ /index.php$is_args$args;
        }

        location ~ \.php$ {
            cache_turbo         ct;
            cache_turbo_backend textpattern;
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

For a subdirectory install, declare it: `cache_turbo_backend_prefix /blog/;`.

## Origin failure: stale-if-error

By default this module serves a stale cached copy when the origin returns 5xx; nginx turns a refused connection into a 502 and a hung one into a 504, so a dead origin is covered. Once the cached copy's TTL has expired, `cache_turbo_keep_stale` supplies the grace window — it defaults to `24h`, and `cache_turbo_keep_stale off` removes it so errors surface normally. Most CMS/app stacks emit no `stale-if-error` of their own. `cache_turbo_use_stale` selects which statuses count as "down" (default: every 5xx); naming tokens replaces the default rather than extending it. Nothing was ever cached for a URL ⇒ nothing to serve; `error_page 502 503 504 /maintenance.html` is the nicer failure.

```nginx
cache_turbo_keep_stale   2h;
cache_turbo_valid   120s;
```

The copy stays fresh for `120s`; if the origin starts failing after that, the expired copy keeps being served for up to `2h` (`cache_turbo_keep_stale`). Past that window, or with nothing cached at all, `error_page` is the fallback. See the README sections on [which failures count as "the origin is down"](../README.md#which-failures-count-as-the-origin-is-down) and [what outage handling cannot do](../README.md#what-outage-handling-cannot-do).

## Verify

```bash
# Public article: MISS then HIT.
curl -s -o /dev/null -D- https://example.com/article | grep -i x-cache
curl -s -o /dev/null -D- https://example.com/article | grep -i x-cache

# Editor and admin: never HIT.
curl -s -o /dev/null -D- -H 'Cookie: txp_login_public=token' \
  https://example.com/article | grep -i x-cache
curl -s -o /dev/null -D- https://example.com/textpattern/ | grep -i x-cache
```

Keep TTLs short or purge on publish: the preset separates shared from private
traffic; it does not know when an article changed.
