# OpenCart + cache-turbo

_Last researched: 2026-09-01 (OpenCart 4.1.0.4; account and checkout controller
inventories rechecked)._

OpenCart is the only shipped preset that classifies **entirely on query
arguments**. Treat it as defense in depth on OpenCart 4.1.0.4, not as permission
to override the application's cache policy: OpenCart globally emits
`Cache-Control: no-store, no-cache`, and the preset does not match its
method-qualified route values.

## Preset

```nginx
cache_turbo         ct;
cache_turbo_backend opencart;
```

<!-- markdownlint-disable MD013 -->

| Check | Values |
| --- | --- |
| Cookie substrings | — (deliberately none; see below) |
| URI prefixes | — (everything is `/index.php`) |
| Query args | Base controller values: `route=checkout/{cart,checkout,confirm,success,failure,payment_address,payment_method,shipping_address,shipping_method,register}`, `route=account/{account,login,logout,register,forgotten,edit,password,address,order,wishlist,download,returns,reward,transaction,subscription,newsletter,affiliate,custom_field,tracking,payment_method,authorize,success}`, plus `user_token`, `customer_token` |

<!-- markdownlint-enable MD013 -->

## Why there is no cookie rule

`OCSESSID` (named by `$_['session_name']` in
[`upload/system/config/default.php`](https://github.com/opencart/opencart/blob/4.1.0.4/upload/system/config/default.php),
set in
[`upload/system/framework.php`](https://github.com/opencart/opencart/blob/4.1.0.4/upload/system/framework.php))
is **issued to guests** — a shop has to track an anonymous cart. Worse, login
state never appears in the cookie at all: it lives in
`$this->session->data['customer']`, **server-side only**. The cookie value is an
opaque session id whose guest and customer forms are identical on the wire.

There is therefore nothing for nginx to test. Adding `OCSESSID` as a bypass
cookie would bypass every visitor and disable the cache entirely, while adding
nothing to safety. The argument rules keep base cart and account routes out; the
origin's global no-store header protects method-qualified routes the preset does
not match. The same `OCSESSID` is used for the admin panel; admin authorisation
is carried by the `user_token` **query arg**, which is why that is a preset row.

## Why the routes are enumerated — and why that is incomplete on OpenCart 4

cache-turbo's argument tier compares `NAME=VALUE` by **exact bytes** — "no case
folding, no prefix match". A row written as `route=account/` would match only a
literal `?route=account/` and never `?route=account/login`. It would look
correct, protect nothing, and leave every account page cacheable.

Each base controller route is therefore listed in full. The consequence is that
**a new private controller or method route under `account/` or `checkout/` is
not covered automatically**. The base route lists were taken from
[`upload/catalog/controller/account/`](https://github.com/opencart/opencart/tree/4.1.0.4/upload/catalog/controller/account)
and
[`upload/catalog/controller/checkout/`](https://github.com/opencart/opencart/tree/4.1.0.4/upload/catalog/controller/checkout).

The 2026-09-01 recheck found 22 account controllers and 10 checkout controllers,
and the preset contains one exact base row for each, plus `user_token` and
`customer_token`: 34 argument rules in total. That count is **not** a safety
invariant. OpenCart 4.1.0.4 generates GET routes such as
`checkout/cart.list`, `checkout/payment_method.getMethods` and
`account/order.info`; the preset's exact `route=checkout/cart` row matches none
of them. OpenCart also converts `|` to the method separator after nginx sees the
query, so `checkout/cart|list` (including URL-encoded `%7C`) has the same gap.
Many account method routes also carry `customer_token`, but cart and checkout
method routes do not.

OpenCart's [`system/framework.php`](https://github.com/opencart/opencart/blob/4.1.0.4/upload/system/framework.php)
globally sends `Cache-Control: no-store, no-cache, must-revalidate`, so
`cache_turbo_backend opencart` (which implies `cache_turbo_cache_control honor`)
stores no application pages. That is safe, but it means the stock vhost below
should produce no `HIT`. Setting `cache_turbo_cache_control ignore` without a
separate fail-closed classifier removes that safety boundary and can cache a
cart method response under a shared key.

## Safe default vhost

```nginx
http {
    cache_turbo_zone name=ct 256m;

    upstream opencart {
        server 127.0.0.1:9000;
        keepalive 32;
    }

    server {
        server_name shop.example.com;

        # The admin directory is renameable at install and cannot be shipped in
        # a preset. Add yours here.
        location /admin/ {
            proxy_pass http://opencart;
        }

        location / {
            cache_turbo         ct;
            cache_turbo_backend opencart;
            cache_turbo_key     $scheme$host$uri$is_args$args;
            cache_turbo_valid   60s;
            cache_turbo_preset  conservative;

            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_http_version 1.1;
            proxy_pass http://opencart;
        }
    }
}
```

`cache_turbo_key` **must** include `$is_args$args`. With a `$uri`-only key every
`?route=` variant collapses onto the single `/index.php` entry. With stock
OpenCart 4.1.0.4 headers this vhost is a safe integration check, not a useful
page cache: expect origin responses rather than `MISS`/`HIT` storage.

## Do not override the stock no-store policy

There is no safe stock-nginx allowlist for shared OpenCart catalogue caching.
Product and category responses can vary with server-side customer state, while
the guest and logged-in forms of `OCSESSID` are indistinguishable to nginx.
A route that looks public is therefore not proof that its response is shared.

Keep `cache_turbo_cache_control honor`. An opt-in requires an application change
that exposes a verified logged-in/guest boundary in the request, such as a
dedicated cookie maintained by the application. Pair that signal with
`cache_turbo_bypass` and `cache_turbo_no_store`, then separately review the
routes and cache key. Do not set `cache_turbo_cache_control ignore` based only
on a route allowlist.

## Verify and caveats

```bash
check_uncached() {
  for attempt in 1 2; do
    curl -s -o /dev/null -D- -H 'Cookie: OCSESSID=abc123' "$1" \
      | grep -Ei '^(cache-control|x-cache):'
  done
}

# Both attempts must show Cache-Control: no-store and must never show X-Cache: HIT.
check_uncached 'https://shop.example.com/index.php?route=product/category&path=20'
check_uncached 'https://shop.example.com/index.php?route=checkout/cart'
check_uncached 'https://shop.example.com/index.php?route=checkout/cart.list'
check_uncached 'https://shop.example.com/index.php?route=account/order'
check_uncached 'https://shop.example.com/index.php?route=common/home&user_token=x'
```

- **SEO-friendly URLs change the picture.** With the SEO URL feature enabled,
  OpenCart rewrites pretty paths back to `index.php?route=…` internally. Whether
  the preset still sees the route depends on where the rewrite happens: if nginx
  rewrites before cache-turbo runs, `r->uri` is already `/index.php` and
  `r->args` carries the route, and the preset works. If the rewrite happens
  inside PHP, the module sees only the pretty path and **the arg rules never
  fire**. Verify with the `curl`s above against your own pretty URLs before
  trusting it, and fall back to a `map $request_uri` rule if needed.
- The `/admin/` directory is renameable at install. It is not in the preset;
  route it around the cache yourself, as in the vhost above.
- **No key cookies.** OpenCart 4.x drives language and currency through the
  URL —
  [`catalog/controller/common/language.php`][opencart-language]
  only reads the request/config and redirects with the argument, setting no
  cookie. The 3.x-era `language` / `currency` cookies were checked for and are
  **not** set by 4.x; do not add them back without re-verifying against your own
  install.
- Keep `cache_turbo_cache_control honor`. OpenCart 4.1.0.4 emits `no-store`
  globally, not only on checkout; the unconditional `Set-Cookie` floor is an
  additional guard, not a replacement.

[opencart-language]: https://github.com/opencart/opencart/blob/4.1.0.4/upload/catalog/controller/common/language.php

## Origin failure: stale-if-error

By default this module can serve a stale cached copy when the origin returns 5xx; nginx turns a refused connection into a 502 and a hung one into a 504, so a dead origin is covered. If the response supplies no `stale-if-error`, `cache_turbo_keep_stale` provides the fallback window — it defaults to `24h`, and `cache_turbo_keep_stale off` removes that fallback. An honored response `stale-if-error` takes precedence, while an honored `must-revalidate` forbids stale serving. `cache_turbo_use_stale` selects which statuses count as "down" (default: every 5xx); listing any tokens replaces the default rather than extending it. Nothing was ever cached for a URL ⇒ nothing to serve; `error_page 502 503 504 /maintenance.html` is the final fallback.

```nginx
cache_turbo_keep_stale   2h;
cache_turbo_valid   60s;
```

The copy stays fresh for `60s`; if the origin starts failing after that, the expired copy keeps being served for up to `2h` (`cache_turbo_keep_stale`). Past that window, or with nothing cached at all, `error_page` is the fallback. See the README sections on [which failures count as "the origin is down"](../README.md#which-failures-count-as-the-origin-is-down) and [what outage handling cannot do](../README.md#what-outage-handling-cannot-do).

## See also

- [README.md](README.md) — the docs index and the full preset table.
- [prestashop.md](prestashop.md) — the other shop researched in this pass, which
  gets **no** preset: its identity lives inside an encrypted cookie.
- [redmine.md](redmine.md), [flarum.md](flarum.md) — shipped in the same pass.
