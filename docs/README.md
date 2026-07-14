# cache-turbo docs

Per-application guides. The [main README](../README.md) is the reference for
every directive; these pages are the *applied* version — a working vhost, the
cookie/key decisions, and the specific ways each application can bite you.

## CMS / application presets

One page per `cache_turbo_backend` preset:

| Preset | Guide | Protects logged-in users out of the box? |
|---|---|---|
| `wordpress` | [wordpress.md](wordpress.md) | ✅ yes (`wordpress_logged_in_*`) |
| `woocommerce` | [woocommerce.md](woocommerce.md) | ✅ yes — **but must be stacked with `wordpress`** |
| `joomla` | [joomla.md](joomla.md) | ❌ **no** — you must add a `cache_turbo_bypass` for the session cookie |
| `xenforo` | [xenforo.md](xenforo.md) | ✅ yes (`xf_user`, `xf_session_admin`) |
| `discourse` | [discourse.md](discourse.md) | ✅ yes (`_t`) — and the origin sends `no-store` anyway |
| `phpbb` | [phpbb.md](phpbb.md) | ❌ **no** — you must add a `cache_turbo_bypass`, and it needs a *value* test |
| `drupal` | [drupal.md](drupal.md) | ⚠️ via the origin — Drupal sends `Cache-Control: private`; no cookie rule shipped |
| `mediawiki` | [mediawiki.md](mediawiki.md) | ✅ yes (`*UserID`, `*UserName`) |
| `magento` | [magento.md](magento.md) | ✅ yes (`X-Magento-Vary`) — and the origin sends `no-store` on cart/checkout |
| `ghost` | [ghost.md](ghost.md) | ✅ yes (`ghost-members-ssr`) — **plus `?uuid=`/`?key=`, which auth a member with no cookie** |

## Every preset is opt-in

Name the backends you actually run. They stack, and spaces and `|` are
interchangeable:

```nginx
cache_turbo_backend wordpress woocommerce;      # the same thing,
cache_turbo_backend wordpress|woocommerce;      # spelled three ways
cache_turbo_backend wordpress | woocommerce;
```

`cache_turbo_backend none;` means *no preset here* — it exists to switch off a
preset inherited from the `server` block for one `location`.

> **There is no `generic` / `auto` union any more, and both spellings are now a
> config error.** It used to mean `wordpress` + `woocommerce` + `joomla`, and it
> was never a safe default: it never covered every backend (`auto` on a Drupal or
> XenForo site enabled *nothing* for it), the `woocommerce` in it left
> `/wp-admin/` cacheable unless you also knew to stack `wordpress`, and the
> `joomla` in it ships no cookie rule at all — so `auto` on a Joomla site *looked*
> like it protected logged-in users and did not. A default that is only correct if
> you already know which parts of it are wrong is a footgun with a friendly name.
>
> The error names its replacement, and nginx refuses to start rather than
> silently enabling nothing — which on an existing WordPress config would mean
> quietly caching `/wp-admin/`.

Four rows above are load-bearing:

- **`joomla` does not ship a cookie rule.** Joomla's session cookie is named from
  a hash of the site secret, so no shippable substring matches it. The preset
  guards `/administrator/` and nothing else — a logged-in front-end user is *not*
  protected until you add your own bypass. See [joomla.md](joomla.md).
- **`phpbb` does not ship a cookie rule either, and for a sharper reason.** phpBB
  hands `_u` / `_k` / `_sid` to *every* visitor including guests (an anonymous
  reader gets `_u=1`), so telling a member from a guest needs a **value** test —
  and the preset registry matches cookie *presence*, never value. A `_sid` rule
  would match every guest, zero your hit rate, and still not find a member. The
  guide gives you the `map` that does it properly. phpBB also sends no reliable
  `Cache-Control: private`, so the bypass is the *whole* safety story there.
  See [phpbb.md](phpbb.md).
- **`drupal` ships no cookie rule but is still safe.** The only shippable literal
  (`SESS`) substring-matches `PHPSESSID` and `JSESSIONID` — every other PHP and
  Java app's session cookie — so shipping it would silently zero the hit rate on
  co-hosted apps. Drupal instead defends itself: it sends `Cache-Control: private,
  must-revalidate` on authenticated pages, and `cache_turbo_backend` implies
  `cache_control honor`, which refuses to store that. See [drupal.md](drupal.md).
- **`magento` bypasses `X-Magento-Vary` where upstream *keys* on it — deliberately.**
  Magento's own Varnish VCL hashes that cookie's **value** into the cache key. This
  registry matches cookie **presence**, never value, so keying on it would collapse
  every non-default visitor — customer A, customer B, a EUR guest — into **one shared
  bucket** and serve one customer's cart to another. Bypassing instead is
  correct-but-conservative: the anonymous catalog (the bulk) still caches.
  [magento.md](magento.md) shows the `map` that restores true value-keying — and
  warns that `$cookie_X_Magento_Vary` **silently never matches**, because nginx does
  not translate `-` to `_` for cookie names.
- **`ghost`'s query args are load-bearing.** `authMemberByUuid()` authenticates a
  member purely from `?uuid=&key=` with **no cookie at all**, so a cookie-only rule
  set is not safe — a member's page would be stored under a URL anyone can request.
  See [ghost.md](ghost.md).
- **`mediawiki`'s dynamic surface is in the query args, not the path.** It
  bypasses `veaction=` but deliberately **not** a blanket `action=` — `action=raw`,
  `action=history`, `diff=` and `oldid=` are deterministic, shared and hot, and
  bypassing them is a pure hit-rate loss. Its cookie prefix defaults to the
  *database name*, so the preset matches the `UserID=` / `UserName=` suffixes
  instead. See [mediawiki.md](mediawiki.md).

## Two traps these guides keep pointing at

**"Session" in a cookie name does not mean "logged in."** XenForo's `xf_session`,
Discourse's `_forum_session`, phpBB's `_sid` and MediaWiki's `<prefix>_session`
are all handed to *anonymous* visitors. Putting one in a bypass list drops most of
your traffic out of the cache — a performance bug wearing the costume of a safety
measure. **Check whether a cookie is set for a logged-out visitor before you
bypass on it.**

**A cookie name that isn't stable across installs cannot be a preset rule.**
Joomla hashes it from the site secret; phpBB lets the admin set the prefix;
MediaWiki derives it from the database name; Drupal hashes it from the hostname.
Where no substring can match, these presets ship *no* cookie rule and say so —
rather than shipping one that quietly does nothing. The guide then hands you the
`map` that works on your install.

## Apps we deliberately do *not* ship a preset for

A preset is only worth shipping when a meaningful share of an app's traffic is
**anonymous, shared HTML** — pages that are byte-identical for every logged-out
visitor. That is the whole business case for a page cache. For some applications
it is simply not true, and a preset there would be an **attractive nuisance**: it
implies caching the app is a good idea, and someone arriving from the WordPress
preset would reasonably assume it does the same job. It cannot.

The answer for these is `cache_turbo off;` — which is already the default.

**Nextcloud.** No anonymous shared surface exists. `/` redirects to `/login`;
`/login` is unique per visitor (it embeds a fresh CSRF token and bootstraps
`oc_sessionPassphrase`) and must never be cached; `/s/<token>` public shares are
random per-token URLs whose audience is a handful of people, so their hit ratio is
≈ 0 while caching them risks serving a **revoked, expired, or password-protected**
share. The bulk of a real instance's requests are WebDAV sync clients and
`/ocs/*` polling — authenticated and per-user. Nextcloud correctly marks its app
responses `Cache-Control: no-cache, no-store, must-revalidate`
(`lib/public/AppFramework/Http/Response.php`), so a cache that honours the origin
(which `cache_turbo_backend` implies) would store *nothing* anyway — a preset could
only "work" by overriding that, which is the dangerous direction. Nextcloud's own
reverse-proxy docs endorse caching **static assets only**, which its stock config
already handles with `immutable` far-future headers. If Nextcloud feels slow the
fix is APCu/Redis, opcache, and `php-fpm` pool sizing — not an HTTP page cache.

**Vaultwarden, vimbadmin, Roundcube** and friends. Same shape: the entire
anonymous surface is a login page, so a preset would be a list that says "bypass
everything". Vaultwarden especially — a preset there is an invitation to
misconfigure a password vault.

**Moodle.** The Nextcloud case twice over. It starts a session and sets
`MoodleSession` for *every* visitor including anonymous ones (`lib/setup.php`), so
a bypass on it would bypass **100%** of requests. Independently, `send_headers()`
(`lib/weblib.php`) emits `Cache-Control: private, max-age=0` at *best* and
`no-store, no-cache` otherwise — so a cache that honours the origin stores nothing
anyway. It is also commonly installed in a subdirectory, which breaks position-0
prefix matching. Three independent failures.

**PrestaShop.** The cookie name is `PrestaShop-<md5(version + name + domain)>` —
per-install *and* it changes on every minor upgrade — and auth state lives **inside
that cookie's encrypted value**, invisible to a presence matcher. Its cart/account
paths are operator- and language-editable via a database `meta` table (`/panier`,
`/mein-konto`), so no prefix is shippable either. And decisively: **PrestaShop 8
sends no `Cache-Control` on cart or checkout at all**, so the origin backstop that
saves Drupal and MediaWiki does not fire. All three legs are broken — a URI-only
preset here would not degrade gracefully, it would **leak carts**.

**OpenCart.** Everything is `index.php?route=checkout/cart`, so the dynamic surface
lives in a query-arg **value**. This registry matches arg-**key** presence, and a
`route` rule would match *every* page including the entire catalog — hit rate zero.
Every cookie OpenCart sets (`OCSESSID`, `currency`) is set for anonymous visitors,
so none can be a bypass. The preset simply cannot express the app.

**The test to apply before asking for a new preset:** *what fraction of this app's
requests are pages a logged-out stranger can see, that look the same for every
logged-out stranger?* If the answer is "basically none", the app does not want a
page cache, and no preset will change that. Note this is **not** about whether the
app is proxied or PHP or Rails — it is only about the anonymous-shared fraction.

## The rule the presets encode

Every one of these guides is an application of the same split:

> **Key on the *variant*. Bypass the *identity*.**

A **variant** (theme, language, device) changes how a page renders but the page is
still shared by everyone who picked that variant — so it belongs in
`cache_turbo_key`. An **identity** (who you're logged in as, what's in your
basket) is shared with nobody — so it belongs in `cache_turbo_bypass`, which means
the response is *never captured*.

Putting a session cookie in the **key** instead of the bypass is the classic
mistake: it doesn't share anything (one entry per visitor, hit rate ≈ 0) *and* it
still stores authenticated HTML. It looks like caching and is neither safe nor
fast. Each guide has a worked example.

## Universal safety floors

These hold regardless of preset, and are not configurable away:

- A response carrying **`Set-Cookie`** is never stored.
- A request carrying **`Authorization`** is never cached.

A preset *widens* the net for application-specific surfaces those floors miss (an
admin URL with no cookie yet, a search query, a cart page). It does not replace
them — and it is **not a security boundary for your own private routes**. A custom
`/members/` area still needs its own `cache_turbo_bypass`.

## See also

- [Main README](../README.md) — every directive, full syntax
- [CMS backends](../README.md#cms-backends-cache_turbo_backend) — the preset table
- [The cache key](../README.md#the-cache-key) — normalization and `$cache_turbo_normalized_args`
- [Redis L2](../README.md#redis-l2-shared-cache) — sharing one cache across a fleet
- [BENCHMARK.md](../BENCHMARK.md) — numbers
