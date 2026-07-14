# WooCommerce + cache-turbo

Caching a WooCommerce store. This is the highest-stakes preset in the set — a
mis-cached cart or checkout page leaks one customer's basket (or address) to the
next visitor. Read the [gotchas](#gotchas) before going live.

- [The short version](#the-short-version)
- [What the preset skips](#what-the-preset-skips)
- [The cart-cookie problem](#the-cart-cookie-problem)
- [Vhost](#vhost)
- [Vhost + Redis L2](#vhost--redis-l2)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)

## The short version

WooCommerce is an **add-on** to WordPress, and so is its preset. Stack them:

```nginx
cache_turbo         ct;
cache_turbo_backend wordpress woocommerce;
```

Naming `woocommerce` alone would cache `/wp-admin/` — the WooCommerce preset only
adds the shop surfaces, it does not repeat the WordPress ones. **Always stack.**

(This is one of the reasons the old `generic`/`auto` union was removed: it
contained `woocommerce`, so it *looked* like a safe one-word default for a shop
while quietly depending on you knowing it also had to contain `wordpress`. A
default that is only correct if you already know which parts of it are wrong is
not a default. Both spellings are now a config error that names the replacement.)

## What the preset skips

| Check | Values |
|---|---|
| URI prefixes | `/cart`, `/checkout`, `/my-account` |
| Query args | `wc-ajax` |
| Cookie substrings | `woocommerce_items_in_cart`, `woocommerce_cart_hash`, `wp_woocommerce_session_` |

Plus everything the `wordpress` preset skips, when stacked.

## The cart-cookie problem

This is the bit that catches people, and it's worth understanding rather than
copying.

A WooCommerce visitor is **anonymous until they add something to the cart.**
Before that, they have no cart cookie, and every page — including the product
pages and the shop archive — is genuinely shared and cacheable. That's most of
your traffic and where all the win is.

The moment they add to the cart, WooCommerce sets `woocommerce_items_in_cart` and
`woocommerce_cart_hash`. From then on **every page they load is different**,
because the theme renders a cart widget ("3 items — €42") into the header of
every page. So the preset bypasses on those cookies *globally*, not just on
`/cart` — a shopper with a full basket gets no cached pages at all.

That is correct, and it is also why a busy store's hit rate is lower than a
blog's. The alternative — caching the page and letting the cart widget be wrong —
means showing customer A's basket count to customer B. Don't.

**If you want cached pages for shoppers with a basket**, the fix is not in nginx:
make the cart widget load client-side (a small `fetch` to a `/wp-json/` cart
endpoint, or WooCommerce's own cart fragments AJAX), so the *page* HTML is
identical for everyone and only the widget differs. Then the cart cookies stop
mattering for the page cache and you can narrow the bypass to the cart/checkout
URIs only:

```nginx
# ONLY if your theme renders no per-user state into shared pages.
# Verify with a diff of the anonymous vs. basket-holding HTML before doing this.
cache_turbo_backend wordpress;              # skip the woocommerce cookie bypass
cache_turbo_bypass  $woo_dynamic;           # keep the URI bypass
```

with, in `http`:

```nginx
map $uri $woo_dynamic {
    default                             "";
    "~^/(cart|checkout|my-account)"     "1";
}
```

Do **not** do this on a stock theme. Check first: load a product page anonymously,
add an item, load it again, and diff the HTML. If anything differs outside the
cart widget, keep the cookie bypass.

## Vhost

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    server {
        listen 443 ssl http2;
        server_name shop.example.com;
        root /var/www/wordpress;
        index index.php;

        location / {
            try_files $uri $uri/ /index.php?$args;
        }

        location ~ \.php$ {
            cache_turbo               ct;
            cache_turbo_backend       wordpress woocommerce;   # STACK both

            cache_turbo_valid         60s;
            cache_turbo_valid         404 410 1m;
            cache_turbo_preset        balanced;

            # Belt and braces on top of the preset: three independent floors.
            cache_turbo_no_store      $cookie_woocommerce_items_in_cart;
            cache_turbo_no_store      $cookie_wp_woocommerce_session_;
            cache_turbo_no_store      $cookie_wordpress_logged_in_;

            include                   fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_pass  unix:/run/php/php-fpm.sock;
        }

        # WooCommerce's cart-fragments AJAX must never be cached.
        location = /?wc-ajax=get_refreshed_fragments {
            cache_turbo off;
            include     fastcgi_params;
            fastcgi_pass unix:/run/php/php-fpm.sock;
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

In `http`, as for WordPress:

```nginx
cache_turbo_redis redis://10.0.0.5:6379/0 prefix=shop: timeout=250ms
                  keepalive=32 keepalive_timeout=60s;
```

> On a store this matters more than usual: **give it its own Redis DB**. Woo's
> sessions often live in Redis too, and a `?all=1` page-cache purge that also
> drops `wp_woocommerce_session_*` logs every shopper out of their basket.

## Checking it works

```nginx
add_header X-Cache-Turbo $cache_turbo_status always;
```

```bash
# anonymous product page: MISS then HIT
curl -sI https://shop.example.com/product/widget/ | grep -i x-cache-turbo
curl -sI https://shop.example.com/product/widget/ | grep -i x-cache-turbo   # HIT

# these must ALWAYS be BYPASS — check every one before launch
curl -sI https://shop.example.com/cart/       | grep -i x-cache-turbo
curl -sI https://shop.example.com/checkout/   | grep -i x-cache-turbo
curl -sI https://shop.example.com/my-account/ | grep -i x-cache-turbo

# a shopper with a basket: BYPASS on *every* page, not just /cart
curl -sI -H 'Cookie: woocommerce_items_in_cart=1' \
     https://shop.example.com/product/widget/ | grep -i x-cache-turbo       # BYPASS
```

The last one is the important test. If a request carrying
`woocommerce_items_in_cart` returns `HIT` on a *product* page, your cart widget is
about to be wrong for somebody.

## Gotchas

- **Never name `woocommerce` alone.** It doesn't include the WordPress rules, so
  `/wp-admin/` and `wordpress_logged_in_*` would be cacheable. Stack:
  `cache_turbo_backend wordpress woocommerce;`.
- **The URI prefixes are matched from the site root** and are *prefixes*, so
  `/cart` also covers `/cart/`, and — watch out — a product literally named
  `/cart-accessories/` would be bypassed too. Rename the product or accept it.
- **A store on a subdirectory or a translated store** shifts these URIs
  (`/fr/panier`), and the preset will not match them. Add a `map`-driven
  `cache_turbo_bypass` for the translated paths; the *cookie* half of the preset
  is path-independent and keeps protecting you regardless.
- **Cart fragments — the preset now covers this, and it is the reason the arg rule
  exists.** WooCommerce refreshes the cart widget over AJAX, and its endpoints have
  **no path of their own**: `get_endpoint()` builds `currentpageurl?wc-ajax=name`,
  so a fragment call is a request to an *ordinary, cacheable page URL* —
  `/?wc-ajax=get_refreshed_fragments` is a request to your **home page**. None of
  `/cart`, `/checkout` or `/my-account` match it. The response body is that
  shopper's basket, and a cached fragment is a leaked basket served to every
  subsequent visitor. The `wc-ajax` arg rule is what closes this; it is the one
  WooCommerce leak path that no URI rule can reach.
- **Prices per customer role** (wholesale plugins, tax by geography) make product
  pages *not* shared even for anonymous visitors. If you run one of those, the
  page cache needs the role/region in the key, or it needs to be off. This preset
  will not save you.
- **`Set-Cookie` responses are never stored** regardless of preset — Woo sets
  cookies liberally, which is a large part of why store hit rates look low.

## See also

- [`wordpress.md`](wordpress.md) — the base preset you must stack with
- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/README.md`](README.md) — all presets
