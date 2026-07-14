# Magento 2 + cache-turbo

Caching a Magento 2 (2.4.x) store. Magento is the **best-behaved application in
this set** — it is *architecturally designed* to sit behind a shared cache, it
ships its own reference Varnish VCL, and it tells you what is cacheable in-band
via `Cache-Control`. This preset is that VCL, translated — with **one deliberate
deviation you must understand**, because copying upstream naively here would leak
one customer's cart to another.

- [The short version](#the-short-version)
- [Why this can replace Varnish](#why-this-can-replace-varnish)
- [`X-Magento-Vary`: the one cookie, and the trap](#x-magento-vary-the-one-cookie-and-the-trap)
- [Recovering the logged-in hit rate](#recovering-the-logged-in-hit-rate)
- [Cookies that must NOT bypass](#cookies-that-must-not-bypass)
- [Vhost](#vhost)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend magento;      # implies cache_turbo_cache_control honor
```

Set Magento's cache application to **Built-in**, not Varnish (see
[Gotchas](#gotchas)). That's it for a correct, safe config.

## Why this can replace Varnish

Magento ships a built-in Full Page Cache, but a hit still requires a **full PHP
bootstrap** — autoloader, DI container, plugin chain — before it can look the page
up. It saves the *rendering*, not the *stack*: a hit is still tens of milliseconds
and a PHP-FPM worker slot. That is why Adobe's own docs push you to a reverse proxy
in production and why Magento generates a Varnish VCL for you.

cache-turbo answers from shm/disk **without touching PHP at all**. On the same hit
that is one to two orders of magnitude better than the built-in FPC — the niche
Varnish currently occupies. If the preset works for you, you can drop Varnish from
the stack entirely.

What makes it safe is that Magento does the hard part itself:

- **Anonymous catalog pages are genuinely shared.** All per-user state (cart
  contents, customer name, messages) is fetched *after* page load by JS from
  `/customer/section/load`. The HTML of a category or product page, for an
  anonymous default-context visitor, is byte-identical for every such visitor.
- **The dangerous pages say so.** Cart, checkout, checkout-success and the customer
  account layouts are all `cacheable="false"`, so Magento emits
  `Cache-Control: no-store, no-cache, must-revalidate` on them
  (`Framework/App/Response/Http.php::setNoCacheHeaders`). `cache_turbo_backend`
  implies `cache_control honor`, which **refuses to store that** — so those pages
  are protected *before a single preset rule runs*. The URI list below is
  defence-in-depth, not the primary control.

## `X-Magento-Vary`: the one cookie, and the trap

| Check | Values |
|---|---|
| URI prefixes | `/checkout`, `/customer`, `/graphql`, `/sales`, `/newsletter`, `/wishlist`, `/paypal`, `/review`, `/page_cache/block/esi`, `/health_check.php` |
| Query args | — |
| Cookie substrings | `X-Magento-Vary` |

`X-Magento-Vary` is Magento's *"this visitor is not the shared anonymous case"*
signal. It is a salted hash of the **vary context** — customer group, auth flag,
currency, store view — and `getVaryString()`
(`Framework/App/Http/Context.php`) computes it **only from values that differ from
their defaults**:

- A plain anonymous visitor on the default store/currency has an all-default
  context ⇒ the function returns `null` ⇒ **the cookie is not set** (and is
  actively deleted if stale). This is the traffic you want to cache, and it caches.
- A logged-in customer, a non-default customer group, or a switched
  currency/store ⇒ the cookie **is** set.

**Here is the trap.** Magento's own VCL puts this cookie in the **cache key**:

```vcl
sub vcl_hash {
    if (req.http.cookie ~ "X-Magento-Vary=") {
        hash_data(regsub(req.http.cookie, "^.*?X-Magento-Vary=([^;]+);*.*$", "\1"));
    }
}
```

That hashes the cookie's **value**, giving each context its own cache bucket. The
preset **cannot** do that: its cookie matcher tests *presence*, never value. If it
keyed on presence, then customer A, customer B, and a EUR guest would all hash to
**one shared bucket** — and you would serve one customer's cart to another.

So the preset **bypasses** on it instead. That is correct-but-conservative:
anonymous default-context traffic (the catalog — the bulk, and the entire point)
still caches and is shared; everyone else goes to origin. Nothing leaks.

## Recovering the logged-in hit rate

If you want upstream's behaviour back — non-default visitors cached, correctly
segmented — put the cookie's **value** in the cache key. It must be done with a
`map`:

```nginx
# http context
map $http_cookie $magento_vary {
    default                        "";
    "~X-Magento-Vary=(?<v>[^;]+)"  "$v";
}
```

```nginx
# location context
cache_turbo_backend magento;
cache_turbo_key     $scheme$host$uri$is_args$args$magento_vary;
```

Now each vary context gets its own cache entry, exactly like Varnish's
`hash_data`, and a logged-in customer's pages are cached *per context* instead of
bypassed. The bypass rule still fires too, so if you want the hit rate you must
also drop the cookie from the preset's reach — in practice: keep the preset for
its URI rules and add your own key, and accept that the shipped cookie rule makes
this a belt-and-braces config rather than a hit-rate win. (A future
cookie-value-aware preset rule would make this unnecessary.)

> **⚠️ Do not write `$cookie_X_Magento_Vary`.** It looks right and it **silently
> never matches**. nginx does *not* translate `-` to `_` for cookie names (unlike
> request headers, where `$http_x_forwarded_for` works). `$cookie_x_magento_vary`
> is empty for every request, and `$cookie_x-magento-vary` parses as `$cookie_x`
> followed by the literal text `-magento-vary`. Use the `map` above — it is the
> only form that works.

## Cookies that must NOT bypass

Every cookie below is set for **anonymous** visitors. Bypassing on any of them
takes your catalog hit rate to approximately **zero**. None of them is in the
preset, on purpose — and this is the single most valuable thing on this page.

| Cookie | Why it is not a bypass |
|---|---|
| `PHPSESSID` | Magento is PHP with sessions site-wide — **every** visitor gets one. Also renameable, so not even a stable name. |
| `form_key` | The CSRF token. Set **client-side for everyone**, anonymous included. |
| `private_content_version` | Set on **any POST by anyone** — a guest add-to-cart, a newsletter signup — and then persists for **ten years**. Bypassing on it is a slow-motion hit-rate collapse: fine on day one, permanently degrading after. |
| `mage-cache-sessid` | Set by JS for **every** visitor. A client-side cache-validity flag, not auth. |
| `section_data_ids` | Set by JS for **every** visitor. The customer-data version map, not auth. |
| `mage-messages` | Flash-message queue. Anons get these too ("you added X to cart"). |
| `mage-cache-storage` | **Not a cookie at all** — a `localStorage` namespace. It will never appear in a `Cookie` header. |
| `mage-customer-login` | Presence ≠ logged-in: it stores a `true`/`false` **value**, and the storage backend is conditional. Unusable with a presence matcher. |

Magento's own VCL inspects **no cookie at all** for its pass/hash decision — it
leans entirely on `Cache-Control` plus the `X-Magento-Vary` key. That is a strong
hint about which cookies matter, and the answer is: only that one.

## Vhost

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 512m;

    # Optional: recover the logged-in hit rate by keying on the vary context.
    # See "Recovering the logged-in hit rate" -- note this MUST be a map.
    map $http_cookie $magento_vary {
        default                       "";
        "~X-Magento-Vary=(?<v>[^;]+)" "$v";
    }

    upstream fastcgi_backend { server unix:/run/php/php-fpm.sock; }

    server {
        listen 443 ssl http2;
        server_name shop.example.com;
        set $MAGE_ROOT /var/www/magento;
        root $MAGE_ROOT/pub;

        location / {
            try_files $uri $uri/ /index.php$is_args$args;
        }

        location ~ ^/(index|get|static|errors/report|errors/404|errors/503)\.php$ {
            cache_turbo               ct;
            cache_turbo_backend       magento;   # implies cache_control honor

            cache_turbo_key           $scheme$host$uri$is_args$args;
            cache_turbo_valid         300s;      # catalog tolerates a long TTL
            cache_turbo_valid         404 410 1m;
            cache_turbo_preset        balanced;

            fastcgi_pass   fastcgi_backend;
            fastcgi_param  PHP_FLAG "session.auto_start=off";
            fastcgi_param  SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
            fastcgi_param  DOCUMENT_ROOT $realpath_root;
            include        fastcgi_params;
        }

        # Static + media are served straight off disk -- never through the cache
        # module. (Magento's VCL "pass"es these for the same reason.)
        location ~* ^/(static|media)/ {
            cache_turbo off;
            expires max;
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

## Checking it works

```nginx
add_header X-Cache-Turbo $cache_turbo_status always;
```

```bash
# anonymous catalog page: MISS then HIT. This is the money path.
curl -sI https://shop.example.com/some-category | grep -i x-cache-turbo
curl -sI https://shop.example.com/some-category | grep -i x-cache-turbo   # HIT

# cart / checkout / account: BYPASS
curl -sI https://shop.example.com/checkout/cart     | grep -i x-cache-turbo
curl -sI https://shop.example.com/customer/account  | grep -i x-cache-turbo

# THE HIT-RATE CHECK. A GUEST carrying the cookies Magento gives every visitor
# must still be a HIT. If any of these say BYPASS, someone added an anon cookie
# to a bypass list and your catalog cache is now doing nothing.
curl -sI -H 'Cookie: PHPSESSID=abc; form_key=def; private_content_version=1a2b' \
     https://shop.example.com/some-category | grep -i x-cache-turbo        # HIT

# THE SAFETY CHECK. A non-default context (logged in / group / currency) must
# never be served from a shared entry.
curl -sI -H 'Cookie: X-Magento-Vary=9f2a4c1e' \
     https://shop.example.com/some-category | grep -i x-cache-turbo        # BYPASS

# And confirm the origin is doing its half.
curl -sI https://shop.example.com/checkout/cart | grep -i cache-control
# Cache-Control: no-store, no-cache, must-revalidate, max-age=0
```

Run the hit-rate check **and** the safety check before you go live. The first
protects your performance; the second protects your customers.

## Gotchas

- **Set the cache application to "Built-in", not "Varnish".** In Varnish mode
  Magento emits `<esi:include>` tags for private blocks, expecting the proxy to
  resolve them. cache-turbo does not process ESI, so it would serve that markup to
  browsers verbatim. In Built-in mode Magento renders those blocks as JS
  placeholders that the customer-data AJAX fills in — which is exactly what you
  want in front of a non-ESI cache.
  ```bash
  bin/magento config:set system/full_page_cache/caching_application 1   # 1 = Built-in
  ```
- **No tag-based purging.** Varnish invalidates by banning on Magento's
  `X-Magento-Tags` header, so a price change appears immediately. cache-turbo has
  no equivalent, so **content changes appear when the TTL expires**. Size
  `cache_turbo_valid` accordingly — this is the one real capability gap versus
  Varnish, and it is worth knowing before you drop Varnish.
- **`/admin` is deliberately not in the preset.** Magento randomises the admin path
  at install (`admin_` + 7 random base36 characters —
  `Framework/Setup/BackendFrontnameGenerator`), so no shippable prefix could match
  it. It does not need one: the admin panel always sends `no-store, no-cache`,
  which `honor` already refuses. If you want belt-and-braces, give your actual
  admin path its own location:
  ```nginx
  location /admin_k3f9x2q/ { cache_turbo off; }
  ```
- **Strip marketing params from the key.** Magento's VCL removes `utm_*`, `gclid`,
  `fbclid`, `msclkid`, `mc_*`, `srsltid`, `gad_*`, `_gl`, `dclid`, `wbraid`,
  `gbraid` and friends from the URL before hashing, so a hundred ad-tagged
  variants of one product page share **one** cache entry. On a store with paid
  traffic this is worth more hit rate than every bypass rule combined — use
  `cache_turbo_normalize_args` / `$cache_turbo_normalized_args` (see the
  [main README](../README.md#the-cache-key)).
- **`/cart` and `/onepage` are not Magento routes.** The real paths are
  `/checkout/cart` and `/checkout/onepage/*`, both covered by `/checkout`. A
  `/cart` prefix would match nothing on a stock install — and could false-positive
  on a catalog URL key like `/cartridge-refill`.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached, regardless of preset.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/woocommerce.md`](woocommerce.md) — the same shop problem, smaller
- [`docs/README.md`](README.md) — all presets
