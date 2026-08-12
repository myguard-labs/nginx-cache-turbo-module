# PrestaShop + cache-turbo

_Last researched: 2026-07-26 (PrestaShop 8.2.x maintenance line, 9.1.4 current)._

**There is no `prestashop` preset.** PrestaShop breaks the model a preset
encodes — "a cookie whose *name* is present means logged in" — in two independent
ways at once: its session cookie name is a per-install MD5, and, more fatally, it
is handed to every anonymous guest on the very first page render. Bypassing on it
would disable the cache for 100% of front-office traffic.

This page explains the failure precisely, then hands you a hand-rolled vhost that
caches PrestaShop safely using URI rules instead of cookie rules. It is the same
class of problem as [`frameworks.md`](frameworks.md) — a rule we cannot ship
because only you can verify it.

## Why there is no preset

**1. The cookie name is derived per install, but the prefix is not.**
[`classes/Cookie.php`](https://github.com/PrestaShop/PrestaShop/blob/develop/classes/Cookie.php)
builds the wire name as:

```php
$this->_name = 'PrestaShop-' . md5((_PS_VERSION_) . $name . $this->_domain);
```

`$name` is `ps-s<id_shop>` for the front office and `psAdmin` for the back
office. So the literal `PrestaShop-` **is** stable and hardcoded — a substring
rule *could* match it — but the 32-hex tail changes with the PrestaShop version
*and* the domain. That alone would only make the preset coarse, not wrong. The
next point makes it wrong.

**2. Every anonymous guest gets that cookie.**
`FrontController::smartyOutputContent()` calls `$this->context->cookie->write()`
on **every** page render, and an `id_guest` is assigned to visitors who have
never logged in. So the first hit on the homepage by a logged-out stranger
returns `Set-Cookie: PrestaShop-<hash>=…`, and every subsequent request carries
it. A `cache_turbo_bypass` on that cookie bypasses the entire front office. Hit
rate zero, cache doing nothing, no error anywhere. This is the
[Moodle/phpBB trap](README.md#apps-we-deliberately-do-not-ship-a-preset-for)
in a shop's clothing.

**3. Logged-in state is inside the cookie, and nginx cannot read it.** The
discriminator is `id_customer`, stored as a field *within* the cookie value,
which PrestaShop encrypts and checksums with its own cipher before writing. There
is no separate plaintext login cookie to key on. nginx sees opaque ciphertext; a
`map` on `$http_cookie` has nothing to match.

<!-- markdownlint-disable MD013 -->

| | What a preset needs | What PrestaShop gives |
| --- | --- | --- |
| Login cookie name | fixed literal | `PrestaShop-<md5(version+name+domain)>` — stable prefix, per-install tail |
| Set for a guest? | no | **yes, on every render** (`smartyOutputContent()` → `cookie->write()`) |
| Login discriminator | cookie presence | `id_customer` **inside** the encrypted cookie value |
| Admin URI | fixed literal | **randomized at install** (`admin3250jyr2e`) |
| Locale cookie | optional | none in plaintext — `id_lang`/`id_currency` are inside the cipher |

<!-- markdownlint-enable MD013 -->

**4. The admin directory is randomized.** PrestaShop renames `admin/` to a random
suffixed directory (`admin3250jyr2e`, etc.) at install time as a security
measure. A preset cannot ship a literal for it; you must add yours by hand below.

So the workable rule is **URI-based, not cookie-based**: enumerate the private
front-office routes, bypass them, and let `cache_turbo_cache_control honor` be the
backstop everywhere else.

## Reverse-proxy vhost core

The private-URL list below is the friendly-URL default set from
[`install-dev/data/xml/meta.xml`](https://github.com/PrestaShop/PrestaShop/blob/develop/install-dev/data/xml/meta.xml).
**These slugs are per-language and admin-editable in the `meta` DB table** — check
yours before trusting the literals. With friendly URLs *off*, every controller is
reached as `index.php?controller=<name>` instead, which is why the second `map`
covers the query-arg form.

```nginx
http {
    cache_turbo_zone name=ct 256m;

    # Private front-office routes (friendly URLs ON).
    # Verify against your `meta` table: slugs are per-language and editable.
    # ADD YOUR RANDOMIZED ADMIN DIRECTORY HERE -- e.g. /admin3250jyr2e
    map $request_uri $ps_private_path {
        default                          0;
        "~*^/(cart|order|order-confirmation|order-follow|order-slip)(/|\?|$)"   1;
        "~*^/(history|identity|my-account|addresses|address)(/|\?|$)"           1;
        "~*^/(authentication|registration|discount|guest-tracking|password)(/|\?|$)" 1;
        "~*^/module-[^/]+-(payment|validation)(/|\?|$)"                        1;
        # "~*^/admin3250jyr2e(/|$)"                                            1;
    }

    # Same controllers reached via ?controller=<name> (friendly URLs OFF).
    map $arg_controller $ps_private_arg {
        default             0;
        "~*^(cart|order|order-confirmation|order-detail|order-follow|order-slip)$" 1;
        "~*^(history|identity|my-account|addresses|address)$"                      1;
        "~*^(authentication|registration|discount|guest-tracking|password)$"       1;
    }

    map "$ps_private_path$ps_private_arg" $ps_private {
        default  1;
        "00"     0;
    }

    upstream prestashop {
        server 127.0.0.1:9000;
        keepalive 32;
    }

    server {
        server_name shop.example.com;

        location / {
            cache_turbo               ct;

            # No preset applies, so turn the origin backstop on by hand.
            cache_turbo_cache_control honor;

            # bypass = skip the lookup; no_store = also refuse to save it.
            # Bypass alone would still let a private page be STORED under the
            # shared key. Always pair them.
            cache_turbo_bypass        $ps_private;
            cache_turbo_no_store      $ps_private;

            # DELIBERATELY ABSENT: any rule on the PrestaShop-<hash> cookie.
            # smartyOutputContent() writes it for anonymous guests, so a bypass
            # on it bypasses every front-office request. See above.

            cache_turbo_key           $scheme$host$uri$is_args$args;
            cache_turbo_valid         60s;
            cache_turbo_valid         404 410 1m;
            cache_turbo_preset        conservative;

            proxy_set_header Host              $host;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_http_version 1.1;
            proxy_pass http://prestashop;
        }

        # Belt and braces for the randomized admin dir -- edit the literal.
        location ^~ /admin3250jyr2e {
            cache_turbo off;
            proxy_pass http://prestashop;
        }
    }
}
```

## Verify and caveats

```bash
# Product / category page: MISS then HIT.
curl -s -o /dev/null -D- https://shop.example.com/2-clothes | grep -i x-cache
curl -s -o /dev/null -D- https://shop.example.com/2-clothes | grep -i x-cache

# Cart and account: must be BYPASS, both URL forms.
curl -s -o /dev/null -D- https://shop.example.com/cart | grep -i x-cache
curl -s -o /dev/null -D- 'https://shop.example.com/index.php?controller=cart' \
  | grep -i x-cache

# THE CHECK PEOPLE SKIP: a plain guest must NOT be bypassed. If this says
# BYPASS you have accidentally keyed on the guest-issued PrestaShop- cookie
# and your hit rate is zero.
curl -s -o /dev/null -D- https://shop.example.com/ | grep -i x-cache
```

- **A logged-in customer viewing a cacheable page is protected only by
  `honor`.** nginx cannot tell them from a guest — the discriminator is
  `id_customer` inside the encrypted cookie. If your PrestaShop or a module fails
  to send `private`/`no-cache` on customer-personalised pages, that page can be
  stored and served to strangers. Confirm with:
  `curl -s -o /dev/null -D- -b jar.txt https://shop.example.com/ | grep -i cache-control`
  — if there is no `private`, treat the whole front office as uncacheable for
  logged-in-capable traffic, or bypass on the session cookie and accept a cache
  that only serves first-time visitors.
- **Add your randomized admin directory.** It is unique per install and nothing
  here can guess it. Uncomment the `map` line *and* the `location`.
- **Verify your friendly-URL slugs.** They live in the `meta` table, are
  per-language, and shop owners rename them. A renamed `/cart` silently drops out
  of the bypass.
- **Language is a URL path prefix (`/en/`, `/fr/`), not a cookie.** `id_lang`
  lives inside the cipher, so `$uri` in the cache key already separates
  languages — provided the shop uses URL-prefixed locales. If it does not, do not
  cache: nginx has no way to vary on language.
- **Modules add private routes.** Payment, wishlist, loyalty and B2B modules all
  mount their own controllers. Every one needs a line in the maps.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached regardless of any of the above — but on PrestaShop the
  `Set-Cookie` floor fires on nearly every uncached front-office response, which
  is a further reason the first hit is a MISS rather than a store.

## Origin failure: stale-if-error

By default this module serves a stale cached copy when the origin returns 5xx; nginx turns a refused connection into a 502 and a hung one into a 504, so a dead origin is covered. Once the cached copy's TTL has expired, `cache_turbo_keep_stale` supplies the grace window — it defaults to `24h`, and `cache_turbo_keep_stale off` removes it so errors surface normally. Most CMS/app stacks emit no `stale-if-error` of their own. `cache_turbo_use_stale` selects which statuses count as "down" (default: every 5xx); naming tokens replaces the default rather than extending it. Nothing was ever cached for a URL ⇒ nothing to serve; `error_page 502 503 504 /maintenance.html` is the nicer failure.

```nginx
cache_turbo_keep_stale    2h;
cache_turbo_valid         60s;
```

The copy stays fresh for `60s`; if the origin starts failing after that, the expired copy keeps being served for up to `2h` (`cache_turbo_keep_stale`). Past that window, or with nothing cached at all, `error_page` is the fallback. See the README sections on [which failures count as "the origin is down"](../README.md#which-failures-count-as-the-origin-is-down) and [what outage handling cannot do](../README.md#what-outage-handling-cannot-do).

## See also

- [`docs/README.md`](README.md) — all presets and the apps deliberately rejected
- [`docs/frameworks.md`](frameworks.md) — the same "no preset here either"
  reasoning, plus the 3-curl derivation procedure
- [`docs/magento.md`](magento.md) — a shop that *does* get a preset, and why
