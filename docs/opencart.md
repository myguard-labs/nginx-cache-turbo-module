# OpenCart + cache-turbo

_Last researched: 2026-07-26 (opencart/opencart `master`, 4.1.0.3 current)._

OpenCart is the only shipped preset that classifies **entirely on query
arguments**. That is not a stylistic choice — OpenCart routes every page through
`index.php?route=<controller>`, so the cart, the account area and the product
catalogue all share a single URL path. A URI-prefix rule would match nothing.

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
| Query args | `route=checkout/{cart,checkout,confirm,success,failure,payment_address,payment_method,shipping_address,shipping_method,register}`, `route=account/{account,login,logout,register,forgotten,edit,password,address,order,wishlist,download,returns,reward,transaction,subscription,newsletter,affiliate,custom_field,tracking,payment_method,authorize,success}`, `user_token`, `customer_token` |

<!-- markdownlint-enable MD013 -->

## Why there is no cookie rule

`OCSESSID` (named by `$_['session_name']` in
[`upload/system/config/default.php`](https://github.com/opencart/opencart/blob/master/upload/system/config/default.php),
set in
[`upload/system/framework.php`](https://github.com/opencart/opencart/blob/master/upload/system/framework.php))
is **issued to guests** — a shop has to track an anonymous cart. Worse, login
state never appears in the cookie at all: it lives in
`$this->session->data['customer']`, **server-side only**. The cookie value is an
opaque session id whose guest and customer forms are identical on the wire.

There is therefore nothing for nginx to test. Adding `OCSESSID` as a bypass
cookie would bypass every visitor and disable the cache entirely, while adding
nothing to safety — the arg rules are what actually keep carts and account pages
out. The same `OCSESSID` is used for the admin panel; admin authorisation is
carried by the `user_token` **query arg**, which is why that is a preset row.

## Why the routes are enumerated

cache-turbo's argument tier compares `NAME=VALUE` by **exact bytes** — "no case
folding, no prefix match". A row written as `route=account/` would match only a
literal `?route=account/` and never `?route=account/login`. It would look
correct, protect nothing, and leave every account page cacheable.

Each private route is therefore listed in full. The consequence is that **a new
private controller under `account/` or `checkout/` is not covered
automatically** — adding one to OpenCart means adding a row to the preset. The
route lists were taken from
[`upload/catalog/controller/account/`](https://github.com/opencart/opencart/tree/master/upload/catalog/controller/account)
and
[`upload/catalog/controller/checkout/`](https://github.com/opencart/opencart/tree/master/upload/catalog/controller/checkout).

## Reverse-proxy vhost core

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
`?route=` variant collapses onto the single `/index.php` entry and the cache
would serve the cart to someone asking for the home page.

## Verify and caveats

```bash
# Catalogue: MISS then HIT, even while carrying a session cookie.
curl -s -o /dev/null -D- -H 'Cookie: OCSESSID=abc123' \
  'https://shop.example.com/index.php?route=product/category&path=20' | grep -i x-cache
curl -s -o /dev/null -D- -H 'Cookie: OCSESSID=abc123' \
  'https://shop.example.com/index.php?route=product/category&path=20' | grep -i x-cache

# Cart, account and admin token: never HIT.
curl -s -o /dev/null -D- 'https://shop.example.com/index.php?route=checkout/cart' | grep -i x-cache
curl -s -o /dev/null -D- 'https://shop.example.com/index.php?route=account/order' | grep -i x-cache
curl -s -o /dev/null -D- 'https://shop.example.com/index.php?route=common/home&user_token=x' | grep -i x-cache
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
- **No key cookies.** OpenCart 4.x drives language and currency through the URL —
  [`catalog/controller/common/language.php`](https://github.com/opencart/opencart/blob/master/upload/catalog/controller/common/language.php)
  only reads the request/config and redirects with the argument, setting no
  cookie. The 3.x-era `language` / `currency` cookies were checked for and are
  **not** set by 4.x; do not add them back without re-verifying against your own
  install.
- Keep `cache_turbo_cache_control honor`; OpenCart emits `no-store` on the
  checkout flow and the `Set-Cookie` floor backs it up.

## Origin failure: stale-if-error

By default this module serves a stale cached copy when the origin returns 5xx; nginx turns a refused connection into a 502 and a hung one into a 504, so a dead origin is covered. Once the cached copy's TTL has expired there is no grace window unless one is configured — `cache_turbo_keep_stale <time>` supplies it, and it defaults to `off`. Most CMS/app stacks emit no `stale-if-error` of their own. `cache_turbo_use_stale` selects which statuses count as "down" (default: every 5xx); naming tokens replaces the default rather than extending it. Nothing was ever cached for a URL ⇒ nothing to serve; `error_page 502 503 504 /maintenance.html` is the nicer failure.

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
