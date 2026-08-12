# Dotclear + cache-turbo

_Last researched: 2026-07-26 (Dotclear `master`)._

Dotclear's published blog frontend is a useful shared-cache surface. It
configures a per-blog session name but does not start that session for ordinary
public rendering; the backend always starts one. Password-protected content and
preview URLs need separate guards.

## Preset

```nginx
cache_turbo         ct;
cache_turbo_backend dotclear;
```

<!-- markdownlint-disable MD013 -->

| Check | Values |
| --- | --- |
| Cookie substrings | `dcxd`, `dc_admin=`, `dc_passwd=` |
| URI prefixes | `/admin`, `/preview`, `/pagespreview` |
| Query args | — |

<!-- markdownlint-enable MD013 -->

Dotclear defaults `DC_SESSION_NAME` to `dcxd` and exposes `DC_ADMIN_URL` as a
deployment setting in
[`Config.php`](https://github.com/dotclear/dotclear/blob/master/src/Core/Config.php).
The frontend appends the blog ID to that session name without starting it during
ordinary rendering in
[`Frontend/Utility.php`](https://github.com/dotclear/dotclear/blob/master/src/Core/Frontend/Utility.php),
whereas the backend explicitly starts the session and fixes its remember-cookie
name to `dc_admin` in
[`Backend/Utility.php`](https://github.com/dotclear/dotclear/blob/master/src/Core/Backend/Utility.php).

The `dc_passwd` cookie unlocks protected posts and pages. Post previews are
authenticated by a user plus 40-character secret under `/preview` in
[`Url.php`](https://github.com/dotclear/dotclear/blob/master/src/Core/Url.php);
the pages plugin registers the equivalent `/pagespreview` route in
[`Prepend.php`](https://github.com/dotclear/dotclear/blob/master/plugins/pages/src/Prepend.php).

## FastCGI vhost core

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 128m;

    # Keep the original clean route visible after try_files internally redirects
    # PHP traffic to /index.php. cache_turbo_backend's URI tier sees $uri.
    map $request_uri $dotclear_private_route {
        default                                      0;
        ~^/(?:admin|preview|pagespreview)(?:/|\?|$)  1;
    }

    server {
        server_name example.com;
        root /var/www/dotclear;

        location / {
            try_files $uri $uri/ /index.php?$args;
        }

        location ~ \.php$ {
            cache_turbo         ct;
            cache_turbo_backend dotclear;
            cache_turbo_key     $host$request_uri;
            cache_turbo_valid   300s;
            cache_turbo_preset  balanced;
            cache_turbo_bypass  $dotclear_private_route;
            cache_turbo_no_store $dotclear_private_route;

            include fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_pass unix:/run/php/php-fpm.sock;
        }
    }
}
```

## Origin failure: stale-if-error

By default this module serves a stale cached copy when the origin returns 5xx; nginx turns a refused connection into a 502 and a hung one into a 504, so a dead origin is covered. Once the cached copy's TTL has expired there is no grace window unless one is configured — `cache_turbo_keep_stale <time>` supplies it, and it defaults to `24h`. Most CMS/app stacks emit no `stale-if-error` of their own. `cache_turbo_use_stale` selects which statuses count as "down" (default: every 5xx); naming tokens replaces the default rather than extending it. Nothing was ever cached for a URL ⇒ nothing to serve; `error_page 502 503 504 /maintenance.html` is the nicer failure.

```nginx
cache_turbo_keep_stale   2h;
cache_turbo_valid   300s;
```

The copy stays fresh for `300s`; if the origin starts failing after that, the expired copy keeps being served for up to `2h` (`cache_turbo_keep_stale`). Past that window, or with nothing cached at all, `error_page` is the fallback. See the README sections on [which failures count as "the origin is down"](../README.md#which-failures-count-as-the-origin-is-down) and [what outage handling cannot do](../README.md#what-outage-handling-cannot-do).

## Verify and caveats

```bash
# Published post: MISS then HIT when Dotclear's headers permit it.
curl -s -o /dev/null -D- https://example.com/post/example | grep -i x-cache
curl -s -o /dev/null -D- https://example.com/post/example | grep -i x-cache

# Backend, preview and protected-content state: never HIT.
curl -s -o /dev/null -D- https://example.com/admin/ | grep -i x-cache
curl -s -o /dev/null -D- -H 'Cookie: dcxd_blog=session' \
  https://example.com/post/example | grep -i x-cache
curl -s -o /dev/null -D- -H 'Cookie: dc_passwd=encoded' \
  https://example.com/post/protected | grep -i x-cache
```

- `DC_SESSION_NAME` is configurable. If it is not `dcxd`, add the deployed
  name with both `cache_turbo_bypass` and `cache_turbo_no_store`; missing it can
  cache session-dependent frontend output.
- `/admin` is the conventional same-host backend path, but `DC_ADMIN_URL` can
  point elsewhere. Add the actual same-host path to the original-request map,
  or keep a separately hosted admin vhost uncached.
- Keep the original-request map when `try_files` sends clean routes to
  `/index.php`. The preset matcher sees nginx's current `$uri` after that
  internal redirect, while the map deliberately reads `$request_uri`.
- Plugins can start the configured frontend session or introduce new private
  routes. The response `Set-Cookie` floor prevents the first response from being
  stored; the configured session-cookie rule must catch later requests.
- A subdirectory install needs `cache_turbo_backend_prefix /blog/;`.
