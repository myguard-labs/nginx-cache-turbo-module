# Magento 2 + cache-turbo

_Last researched: 2026-07-18_

Caching a Magento 2 (2.4.x) store. Magento is the **best-behaved application in
this set** — it is *architecturally designed* to sit behind a shared cache, it
ships its own reference Varnish VCL, and it tells you what is cacheable in-band
via `Cache-Control`. This preset **is** that VCL, translated, with **one
deliberate and important deviation** ([GraphQL](#gotchas)): it value-keys the one
cookie Magento's own VCL keys on, exactly the way upstream does, but it *bypasses*
`/graphql` where the VCL *caches* it.

- [The short version](#the-short-version)
- [Why this can replace Varnish](#why-this-can-replace-varnish)
- [`X-Magento-Vary`: value-keyed, not bypassed](#x-magento-vary-value-keyed-not-bypassed)
- [The transition race](#the-transition-race)
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
[Gotchas](#gotchas)). That's it for a correct, safe config — the vary cookie is
handled natively, no `map` required.

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

## `X-Magento-Vary`: value-keyed, not bypassed

| Check | Values |
|---|---|
| URI prefixes | `/checkout`, `/customer`, `/graphql`, `/rest`, `/soap`, `/sales`, `/newsletter`, `/wishlist`, `/paypal`, `/review`, `/page_cache/block/esi`, `/health_check.php` |
| Query args | — |
| Key cookies (value folded into cache key) | `X-Magento-Vary` |

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

Magento's own VCL puts this cookie's **value** in the cache key:

```vcl
sub vcl_hash {
    if (req.http.cookie ~ "X-Magento-Vary=") {
        hash_data(regsub(req.http.cookie, "^.*?X-Magento-Vary=([^;]+);*.*$", "\1"));
    }
}
```

`vcl_recv` has **no `return(pass)` on this cookie at all** — Magento's proxy
passes only on URL (checkout, customer, media/static) and non-GET/HEAD methods.
The built-in PHP Full Page Cache agrees:
`Framework/App/PageCache/Identifier.php` folds `COOKIE_VARY_STRING` into the
sha1 cache id. Two independent upstream implementations, one answer — the vary
value is a cache-key component, not a bypass trigger.

**This preset does the same thing**, via a third tier of preset rule —
`key_cookies` — alongside the URI list above: the raw `Cookie:` header is parsed
for `X-Magento-Vary`, and its value is folded into the cache key automatically.
Each vary context (anonymous, logged-in group A, EUR guest, …) gets its own
cache entry, exactly like Varnish's `hash_data`. You do not configure a `map` or
add anything to `cache_turbo_key` — this is intrinsic to the preset.

**Why the old bypass was wrong.** The cookie is a *segment fingerprint*, not an
identity: `Context::getVaryString()` runs `sha256` over the **sorted tuple**
`{customer_group, customer_logged_in, store, currency}`, and `getData()` drops
any field equal to its default. A default anonymous visitor gets **no cookie**.
A guest who merely switched currency or store view gets one — while holding
**zero** private data. Bypassing sent every one of those non-default anonymous
visitors to origin for nothing. The "it stops a cart leak" justification was
also false: the cart is never in the cached HTML. Magento's private-content/
sections JS fetches it client-side after load — that is the entire point of the
architecture. Two logged-in shoppers in the same group/store/currency are
*designed* to receive byte-identical cached HTML; refusing to cache that page
bought no safety and cost real hit rate.

**Why not presence-key either.** Presence-keying (cache once you see the cookie
at all, ignore its value) would collapse a EUR guest, a wholesale customer and a
logged-in retail customer into **one shared bucket** — that genuinely is a
cross-user leak. Value-keying and presence-keying are different mechanisms;
rejecting the second is not an argument for bypass. Value-keying is what
upstream does, and it is safe.

## The transition race

There is one real hazard, and it is invisible from the request side alone: a
request carrying **no** vary cookie hashes to the shared anonymous bucket, but
the *response* can be the one that sets `X-Magento-Vary` (a guest's first
non-default action). Storing that segmented body under the anonymous key would
poison it for every anonymous visitor afterwards.

Magento's own VCL refuses this explicitly, in `vcl_backend_response`:
`beresp.uncacheable = true` when the backend request had no vary cookie but the
backend response sets one.

cache-turbo gets the identical refusal for free, with no magento-specific code:
`ngx_http_cache_turbo_response_cacheable()` has an **unconditional** floor that
never stores any response carrying `Set-Cookie` — and the response that
establishes a new vary segment necessarily carries one. This preset **depends**
on that floor; there is nothing else guarding the transition.

> **⚠️ Do not write `$cookie_X_Magento_Vary`.** It looks right and it **silently
> never matches**. nginx does *not* translate `-` to `_` for cookie names (unlike
> request headers, where `$http_x_forwarded_for` works). `$cookie_x_magento_vary`
> is empty for every request, and `$cookie_x-magento-vary` parses as `$cookie_x`
> followed by the literal text `-magento-vary`. This is exactly why the preset
> parses the raw `Cookie:` header itself instead of relying on nginx's `$cookie_`
> variables — no `map` workaround is needed, or possible to get right by hand.

**Key-cookie name matching is exact**, unlike the tier-2 cookie *predicates*
used by presets like `phpbb` (which match by name suffix). The value goes
straight into the cache key, so a loose match would let an attacker choose which
bucket their request lands in by sending a cookie like `NOT-X-Magento-Vary`. The
predicate engine can afford suffix matching because its failure mode is a
needless bypass; a key cookie cannot, because its failure mode is bucket
selection.

**All `Cookie:` request headers are scanned**, not just the first — a client can
legally split cookies across multiple `Cookie:` headers, and Varnish's own
`std.collect()` exists for the same reason. Scanning only the first header would
let an attacker hide the real vary cookie in a second header and pick their
bucket.

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
hint about which cookies matter, and the answer is: only that one, and only by
value.

## Vhost

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 512m;

    upstream fastcgi_backend { server unix:/run/php/php-fpm.sock; }

    # The preset's URI rules match $uri, which try_files has already rewritten
    # to /index.php by the time the module runs, so the preset's uris[] can
    # never fire on a Magento vhost. Gate the private surfaces on $request_uri
    # instead -- the ORIGINAL request line, which an internal redirect does not
    # touch -- and apply the result inside the .php location below.
    map $request_uri $magento_private {
        default                                          0;
        "~^/(checkout|customer|sales|wishlist)([/?]|$)"   1;
    }

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
                                                  # and value-keys X-Magento-Vary

            # NO cache_turbo_key here. try_files has rewritten $uri to
            # /index.php, so any key built from $uri collapses the WHOLE
            # storefront onto one entry. The module default keys on
            # unparsed_uri (the original request line) and is correct.
            cache_turbo_valid         300s;      # catalog tolerates a long TTL
            cache_turbo_valid         404 410 1m;
            cache_turbo_preset        balanced;

            # Cart / account / order / wishlist: never serve from cache, and
            # never store either. Both directives are required -- bypass alone
            # still stores, which would write a logged-in customer's page into
            # the zone under the original URL.
            #
            # Do NOT try to do this with `location ^~ /checkout { cache_turbo
            # off; }` instead. try_files internally redirects to /index.php,
            # nginx then re-runs the location search, and THIS block's config is
            # what governs the response -- the `cache_turbo off` set in the
            # /checkout block is discarded before the module ever runs.
            cache_turbo_bypass        $magento_private;
            cache_turbo_no_store      $magento_private;

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
curl -s -o /dev/null -D- https://shop.example.com/some-category | grep -i x-cache-turbo
curl -s -o /dev/null -D- https://shop.example.com/some-category | grep -i x-cache-turbo   # HIT

# cart / checkout / account: BYPASS
curl -s -o /dev/null -D- https://shop.example.com/checkout/cart     | grep -i x-cache-turbo
curl -s -o /dev/null -D- https://shop.example.com/customer/account  | grep -i x-cache-turbo

# THE HIT-RATE CHECK. A GUEST carrying the cookies Magento gives every visitor
# must still be a HIT. If any of these say BYPASS, someone added an anon cookie
# to a bypass list and your catalog cache is now doing nothing.
curl -s -o /dev/null -D- -H 'Cookie: PHPSESSID=abc; form_key=def; private_content_version=1a2b' \
     https://shop.example.com/some-category | grep -i x-cache-turbo        # HIT

# THE SEGMENTATION CHECK. Two different vary values must land in two different
# entries -- neither one a HIT off the other's warm-up.
curl -s -o /dev/null -D- -H 'Cookie: X-Magento-Vary=9f2a4c1e' \
     https://shop.example.com/some-category | grep -i x-cache-turbo        # MISS (first time)
curl -s -o /dev/null -D- -H 'Cookie: X-Magento-Vary=9f2a4c1e' \
     https://shop.example.com/some-category | grep -i x-cache-turbo        # HIT (own segment)
curl -s -o /dev/null -D- -H 'Cookie: X-Magento-Vary=deadbeef' \
     https://shop.example.com/some-category | grep -i x-cache-turbo        # MISS (different segment, not the other customer's HIT)

# And confirm the origin is doing its half.
curl -s -o /dev/null -D- https://shop.example.com/checkout/cart | grep -i cache-control
# Cache-Control: no-store, no-cache, must-revalidate, max-age=0
```

Run the hit-rate check **and** the segmentation check before you go live. The
first protects your performance; the second protects your customers — two
different `X-Magento-Vary` values must never share a cache entry.

Note the module never stores `HEAD` responses, so a `curl -sI` HEAD request can
**never** show a `HIT` here — the recipes above are deliberately GET
(`-s -o /dev/null -D-`), not `-sI`.

## The Web API surface (`/rest`, `/soap`, `/graphql`)

These three are **header-authenticated**: a client sends
`Authorization: Bearer <token>` and no cookie at all, so every cookie rule in
the preset is structurally blind to them. `GET /rest/V1/customers/me` returns
that customer's name, e-mail and address book.

The front names come from `app/code/Magento/Webapi/etc/di.xml` (`webapi_rest`
→ `rest`, `webapi_soap` → `soap`). `/graphql` was covered from the start;
`/rest` and `/soap` were its missing twins.

The prefix needs a `/` or `.` boundary after it, so a catalog URL like
`/restaurant-supplies` is **not** matched and still caches normally.

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
- **Tag-based purging works — wire it to `X-Magento-Tags`.** Magento already emits
  the header Varnish bans on; point `cache_turbo_tag` at it and a price change can
  be purged immediately instead of waiting for the TTL. Needs `cache_turbo_redis`
  (tags live in Redis).

  ```nginx
  cache_turbo_tag $upstream_http_x_magento_tags;   # comma-separated; needs redis
  ```
  Then invalidate a group with `POST /_cache?tag=cat_p_42`.

  **Mind the 16-tag cap.** `NGX_HTTP_CACHE_TURBO_MAX_TAGS` is 16, and Magento emits
  **one `cat_p_<id>` tag per product on the page** — so a category page listing more
  than ~16 products overflows it. Tags past the cap are **not indexed**, which means
  a purge of one of them will **not** invalidate that page and you will serve stale
  content. The module logs `tag list truncated at 16 tags` (level `warn`) naming the
  URI whenever this happens — **watch for it**. If your catalog pages trip it, either
  raise `NGX_HTTP_CACHE_TURBO_MAX_TAGS` and rebuild, or fall back to TTL expiry for
  those pages. The cap is a deliberate DoS bound: the tag list is upstream-controlled
  and each tag costs its own Redis round trip, so an unbounded list would let one
  response fire a connection storm.
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
- **`/graphql` is bypassed here, and this is the one place the preset deviates
  from Magento's VCL.** Upstream *caches* GraphQL: `varnish7.vcl` passes only an
  authenticated request that carries no cache id (`req.url ~ "/graphql" &&
  !req.http.X-Magento-Cache-Id && req.http.Authorization ~ "^Bearer"`), and
  otherwise hashes the query on **request headers** —
  `X-Magento-Cache-Id`, an `Authorized` marker, `Store` and `Content-Currency`
  (`sub process_graphql_headers`). cache-turbo keys on the request line and on
  cookie *values*, not on arbitrary request headers, so it cannot reproduce that
  key; bypassing the whole endpoint is the correct-but-conservative equivalent.
  If you serve heavy GraphQL read traffic and want it cached, do it explicitly
  in its own `location /graphql` with `cache_turbo_key` plus
  `cache_turbo_require_header` (see the
  [main README](../README.md#letting-the-origin-decide-cache_turbo_require_header)) —
  not by removing this rule.
- **`/cart` and `/onepage` are not Magento routes.** The real paths are
  `/checkout/cart` and `/checkout/onepage/*`, both covered by `/checkout`. A
  `/cart` prefix would match nothing on a stock install — and could false-positive
  on a catalog URL key like `/cartridge-refill`.
- **A wide vary key range can grow the cache.** Every distinct vary value is its
  own full set of cache entries. On a store with many customer groups or store
  views this is the correct tradeoff (it is what upstream does), but size your
  zone and TTLs with that multiplication in mind.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached, regardless of preset. This is also what protects the
  vary-transition race above — see [The transition race](#the-transition-race).

## PHP settings / gotchas

These are Magento-specific PHP-side facts that decide whether the preset in front
of it is correct and fast. Everything below is verified against Adobe's own docs
and `magento/magento2`; a couple of tuning numbers vary by source and are marked.

- **`X-Magento-Vary` MUST be a cache-key component — this is the correctness
  lynchpin.** Magento hands the same anonymous HTML to every default-context
  visitor, and it segments everything else *only* through this cookie:
  `Framework\App\Http\Context::getVaryString()` returns
  `hash('sha256', $this->serializer->serialize($data) . '|' . $salt)` over the
  `ksort()`ed context tuple — the serializer is Magento's
  `Serialize\Serializer\Json` (the constructor default), **not** PHP's
  `serialize()`, so the hashed bytes are JSON — over
  (customer group, login flag, store, currency) with default-valued fields dropped
  — so an all-default visitor gets `null` and no cookie, and any other segment gets
  a distinct hash. If a cache does not fold that value into its key, a wholesale
  customer, a EUR guest and a logged-in retail shopper collapse into one bucket and
  cross-contaminate. The preset already value-keys it (see
  [above](#x-magento-vary-value-keyed-not-bypassed)); do not defeat that.
- **Magento's FPC is built for Varnish, and it ships the VCL.** Full Page Cache is
  designed around a Varnish-style reverse proxy: Magento emits `X-Magento-Vary` plus
  `Cache-Control`/`Surrogate-Control` and generates a store-specific `varnish6.vcl`
  (`bin/magento varnish:vcl:generate`). The built-in PHP FPC exists as a fallback but
  still pays a full PHP bootstrap per hit. cache-turbo replaces the Varnish tier by
  replicating that VCL's key/pass logic — which is only safe because the *page* stays
  cacheable while all per-user state loads out-of-band.
- **Private content keeps the page cacheable.** Cart, customer name, messages and the
  like are never in the cached HTML — they are fetched after load by the customer-data
  JS from `/customer/section/load/` (driven by each module's `sections.xml`). That is
  what lets an anonymous catalog page be genuinely shared. Never route
  `/customer/section/load/` through the cache; it is covered by the `/customer` prefix
  in the preset.
- **OpCache is effectively required, and must be sized for Magento's file count.**
  Adobe requires `opcache.save_comments=1` — Magento uses code comments/annotations
  for DI code generation, and turning it off breaks compilation. Recommended
  production values: `opcache.memory_consumption=512`,
  `opcache.max_accelerated_files=60000` (Adobe's tested figure; large stores with many
  extensions are commonly tuned higher — 100000–130000 is community-reported, and PHP
  rounds the value up to the next prime), and `opcache.validate_timestamps=0` in
  production (so you MUST flush OpCache on every deploy). Also
  `opcache.interned_strings_buffer` in the tens of MB — it is carved out of
  `memory_consumption`, so budget for it.
- **`memory_limit` ≥ 2G for CLI / bin/magento.** `setup:di:compile`,
  `setup:static-content:deploy` and other `bin/magento` commands need a large heap;
  Adobe recommends 2G (up to ~4G for testing/heavy deploys), typically passed per
  invocation with `php -d memory_limit=4G bin/magento …`. The PHP-FPM pool serving
  page requests can stay lower (768M–2G).
- **`realpath_cache_size=10M`, `realpath_cache_ttl=7200`.** Magento touches a huge
  number of files per request; the default 4K realpath cache thrashes. Adobe calls
  these out explicitly as a performance requirement.
- **`max_execution_time` for indexers and cron.** Reindex (`bin/magento indexer:reindex`)
  and `bin/magento cron:run` can run long; the CLI SAPI ignores `max_execution_time`
  (`0`), but if you drive indexers or setup over an FPM/web path, raise it there or
  they time out mid-run.
- **2.4.8 vary-cookie regression (version-specific, community-reported).** A change in
  Magento 2.4.8 marks a response uncacheable when the request's `X-Magento-Vary` cookie
  does not match the freshly generated vary string — which is *always* true on a first
  request (no cookie yet), reportedly breaking initial cache population
  (`magento/magento2` issue #40272, S0, awaiting triage as of 2026-07). If you see
  first-hit misses that never warm on 2.4.8, check for the upstream fix/patch before
  blaming the preset — cache-turbo's key logic is unaffected.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/woocommerce.md`](woocommerce.md) — the same shop problem, smaller
- [`docs/README.md`](README.md) — all presets
