# cache-turbo docs

Per-application guides. The [main README](../README.md) is the reference for
every directive; these pages are the *applied* version — a working vhost, the
cookie/key decisions, and the specific ways each application can bite you.

## CMS / application presets

One page per `cache_turbo_backend` preset:

| Preset | Guide | Protects logged-in users out of the box? |
|---|---|---|
| `wordpress` | [wordpress.md](wordpress.md) | ✅ yes (`wordpress_logged_in_*`) |
| `woocommerce` | [woocommerce.md](woocommerce.md) | ✅ yes — **but must be stacked with `wordpress`** — plus `?wc-ajax=`, a cart fragment on *any* page URL |
| `joomla` | [joomla.md](joomla.md) | ⚠️ **partial** (`joomla_remember_me_`) — a non-remember-me login is INVISIBLE (md5 session cookie); you must still add a `cache_turbo_bypass` |
| `xenforo` | [xenforo.md](xenforo.md) | ⚠️ yes (`xf_session` + `xf_user` + `xf_session_admin`) — **stock XF has NO login-only cookie**; `xf_session` is guest-issued, so safety costs hit rate. Also bypasses `/api/` (REST, `XF-Api-Key` header) + `_xfToken`, and **value-keys** `xf_style_id`/`xf_style_variation`/`xf_language_id` |
| `discourse` | [discourse.md](discourse.md) | ✅ yes (`_t`) — and the origin sends `no-store` anyway |
| `phpbb` | [phpbb.md](phpbb.md) | ❌ **no** — you must add a `cache_turbo_bypass`, and it needs a *value* test |
| `drupal` | [drupal.md](drupal.md) | ✅ yes (`SESS`) — anon users DO get sessions, so the cookie rule is required; it over-matches `PHPSESSID` by design |
| `mediawiki` | [mediawiki.md](mediawiki.md) | ✅ yes (`*Token`, `*_session`) — **no URI rules: `/index.php` is the article path on a stock wiki** |
| `magento` | [magento.md](magento.md) | ✅ yes (`X-Magento-Vary`, value-keyed) — and the origin sends `no-store` on cart/checkout |
| `shopware6` | [shopware6.md](shopware6.md) | ✅ yes (`sw-cache-hash`, value-keyed) — same engine as `magento` |
| `ghost` | [ghost.md](ghost.md) | ✅ yes (`ghost-members-ssr`) — **plus `?uuid=`/`?key=`/`?gift=`, which auth a member or unlock paid content with no cookie** |
| `wagtail` | [wagtail.md](wagtail.md) | ⚠️ yes (`sessionid`) — **but only while nothing writes the session for guests**; fails safe |
| `kirby` | [kirby.md](kirby.md) | ⚠️ yes (`kirby_session`) — **but a `csrf()` form page cookies guests**; fails safe |
| `typo3` | [typo3.md](typo3.md) | ⚠️ yes (`fe_typo_user`, `be_typo_user`) — **but the cookie name is admin-overridable via `FE/cookieName`**; fails **UNSAFE** |
| `invision` | [invision.md](invision.md) | ✅ yes (`ips4_loggedIn`, vendor-documented for this exact purpose) — closed-source, vendor-attested not code-verified |
| `smf` | [smf.md](smf.md) | ✅ yes (`SMFCookie`, presence-only) — guest-issued too; the ideal value predicate needs JSON/array decoding this engine doesn't do, so it costs hit rate instead |
| `vanilla` | [vanilla.md](vanilla.md) | ✅ yes (`Vanilla`, presence-only) — **verify empirically on your install**, source could not be directly cited |
| `punbb` | [punbb.md](punbb.md) | ✅ yes (`punbb_cookie`, presence-only) — same engine limitation as `smf`, guest-issued too |
| `phorum` | [phorum.md](phorum.md) | ✅ yes (fixed session-cookie constants) — never guest-issued, the clean case |
| `yabb` | [yabb.md](yabb.md) | ✅ yes (`Y2Sess-`/`Y2User-`/`Y2Pass-` prefix) — per-install random suffix, but never guest-issued |
| `mybb` | [mybb.md](mybb.md) | ✅ yes (`{prefix}user` suffix) — never guest-issued |
| `vbulletin` | [vbulletin.md](vbulletin.md) | ✅ yes (`bb_userid`/`bb_password`/`bbimloggedin`) — closed-source, community-corroborated |

## Not an app — a framework? (Django, Laravel, Rails, …)

[frameworks.md](frameworks.md). There is **no `django` or `laravel` preset**, and
there will not be one: a framework supplies none of the three literals a preset is
made of. Laravel's session cookie is `<APP_NAME>_session` (per-install) *and* is
handed to every guest unconditionally; Django's `sessionid` is only guest-free
until someone adds an anonymous cart. The guide gives you the three `curl`s that
derive the correct rule for **your** app, and the `cache_turbo_cache_control honor;`
default that is safe before you do.

If you run an *application* that is built on a framework — Discourse is Rails,
Magento is Laminas/Zend — use that app's preset above, not that page.

## WordPress caching-plugin interop

These are **not** `cache_turbo_backend` presets — there's no new backend keyword
here. Every site below still runs `cache_turbo_backend wordpress;` (or
`wordpress woocommerce`) unchanged. The question these pages answer is narrower:
*"I already run cache-turbo at the nginx layer AND one of these plugins at the WP
layer — how do I configure the plugin so the two don't double-cache, fight over
a purge, or leave a stale race?"* Each page ends in the same shape: disable the
plugin's own HTML page-cache module (cache-turbo is faster and already at the
front), keep the plugin's *other* features (minify, image opt, CDN, object
cache) since those speed up the PHP origin cache-turbo falls through to on a
MISS — genuinely complementary, not redundant.

| Plugin | Guide | Own page-cache engine on stock nginx |
|---|---|---|
| LiteSpeed Cache | [litespeed-cache.md](litespeed-cache.md) | **dormant** — LSCache needs the LiteSpeed web server or its own nginx module; on vanilla nginx only minify/image-opt/CDN/object-cache remain active |
| WP Rocket | [wp-rocket.md](wp-rocket.md) | PHP-level fallback only (no official nginx helper) — disable it |
| WP Super Cache | [wp-super-cache.md](wp-super-cache.md) | Expert/mod_rewrite mode is Apache-only and inert; Simple/PHP mode works but should be turned off |
| WP Fastest Cache | [wp-fastest-cache.md](wp-fastest-cache.md) | `advanced-cache.php` PHP-level cache — disable "Cache System", keep minify/CDN |
| W3 Total Cache | [w3-total-cache.md](w3-total-cache.md) | disable the **Page Cache** module only — Object/Database Cache, Minify, CDN are separate and worth keeping; Redis-DB-separation gotcha if both point at the same instance |
| SG Optimizer | [sg-optimizer.md](sg-optimizer.md) | Dynamic Caching is SiteGround-proxy-only — **inert off SiteGround hosting**, nothing to disable |
| Hummingbird | [hummingbird.md](hummingbird.md) | PHP-level disk cache — disable Page Caching, keep Asset Optimization/CDN |
| NitroPack | [nitropack.md](nitropack.md) | **not a local plugin at all** — an edge/CDN reverse proxy in FRONT of your nginx; cache-turbo still helps on NitroPack's MISS/bypass traffic reaching origin. Real-IP/XFF and dual-purge gotchas |
| Cache Enabler | [cache-enabler.md](cache-enabler.md) | `advanced-cache.php` PHP-level cache — disable it, WebP conversion is independent |
| Breeze | [breeze.md](breeze.md) | disk-based PHP cache; its Varnish toggle is Cloudways-proxy-only and inert off Cloudways |

Membership/paywall plugins (MemberPress, Restrict Content Pro) and WooCommerce
extensions adding cart-like state outside `/cart` are a different, still-open
class — they add genuinely new private surfaces the `wordpress`/`woocommerce`
presets' URI list can't see, not a caching-layer interop question. Not yet
covered here.

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
- **`drupal` ships the `SESS` cookie rule.** Drupal names its session cookie
  `SESS<hash>` (and `SSESS<hash>` over HTTPS), so the `SESS` substring matches every
  install without a per-site literal. It over-matches `PHPSESSID` and `JSESSIONID`
  by design — a co-hosted PHP/Java app's session cookie will also trip it, trading a
  little hit rate on those apps for never serving an authenticated Drupal page. As a
  second floor, Drupal sends `Cache-Control: private, must-revalidate` on
  authenticated pages, and `cache_turbo_backend` implies `cache_control honor`, which
  refuses to store that. See [drupal.md](drupal.md).
- **`magento` value-keys `X-Magento-Vary`, exactly like upstream.** Magento's own
  Varnish VCL hashes that cookie's **value** into the cache key
  (`vcl_hash: hash_data(regsub(...))`) and never passes on it in `vcl_recv`. There
  are three distinct things a preset could do with a cookie, and they are not
  interchangeable: **bypass** (skip the cache whenever the cookie is present) is
  what this preset used to do, and it was wrong — the cookie is a segment
  fingerprint set on *any* non-default context (a EUR guest, a switched store
  view), not an auth flag, and a plain anonymous visitor never gets it at all, so
  bypassing sent every non-default anonymous visitor to origin for nothing while
  buying no real safety (the cart is never in the cached HTML — it's fetched
  client-side). **Presence-keying** (one cache bucket for "cookie present", no
  matter the value) would be a genuine leak — it collapses customer A, customer B,
  and a EUR guest into one shared entry. **Value-keying** (this preset's `key_cookies`
  tier) folds the cookie's actual value into the cache key, giving every vary
  context its own entry — safe, and what both of Magento's own cache
  implementations (Varnish VCL and the built-in PHP FPC) already do. The module
  parses the raw `Cookie:` header itself for this, which is also why
  `$cookie_X_Magento_Vary` (nginx does not translate `-` to `_` for cookie names)
  is no longer something you need to work around. See [magento.md](magento.md).
- **`shopware6` value-keys `sw-cache-hash`, the same engine as `magento`.**
  `CacheHeadersService::buildCacheHash()` folds `{rule_ids, version_id,
  currency_id, tax_state, logged_in_state}` into the cookie's value, and
  Shopware's own Varnish config hashes that same value into the cache key
  (`hash_data("+context=" + cookie.get("sw-cache-hash"))`). Bypassing on
  presence would send cart-holding guests and non-default-currency guests to
  origin for nothing — `isCacheHashRequired()` returns true for them too, and
  their data is never in the cached HTML. `sw-states`/`sw-currency` were
  **removed in 6.8** in favour of this one cookie, so a preset keyed on the old
  cookies would silently stop firing on an upgraded shop. See
  [shopware6.md](shopware6.md).
- **`ghost`'s query args are load-bearing.** `authMemberByUuid()` authenticates a
  member purely from `?uuid=&key=` with **no cookie at all**, so a cookie-only rule
  set is not safe — a member's page would be stored under a URL anyone can request.
  See [ghost.md](ghost.md).
- **`wagtail` and `kirby` are the two *conditional* presets — and the condition
  fails SAFE.** Both ride a cookie that is issued only when a session actually
  exists (Django's `sessionid` via lazy save; Kirby's `kirby_session`), which is
  what makes them shippable at all. But both stop being logged-in signals if the
  app starts writing sessions for guests — a Django anonymous cart, a Kirby
  template calling `csrf()`. When that happens the guest gets **bypassed**: the hit
  rate drops, nothing leaks. **That direction is the whole ballgame** — compare
  `flarum` below, whose equivalent condition fails the *other* way and is therefore
  rejected outright. See [wagtail.md](wagtail.md), [kirby.md](kirby.md).
- **`typo3` is a conditional cookie rule too — but it is the one that fails
  UNSAFE, not safe.** `FrontendUserAuthentication` sets `$dontSetCookie = true`
  by default, so an anonymous visitor gets no `fe_typo_user` cookie — good hit
  rate, same shape as `wagtail`/`kirby`. But the cookie **name** is read from
  `$GLOBALS['TYPO3_CONF_VARS']['FE']['cookieName']` and is admin-overridable,
  not a per-install hash. A site that sets it loses the match silently, and
  because this is a *bypass* rule, a lost match means a logged-in page gets
  **cached and served to strangers** — the opposite failure direction from
  `wagtail`/`kirby`. If you rename the cookie you must add your own
  `cache_turbo_bypass` for it. `be_typo_user` (backend session) is matched too,
  independently — it catches an editor previewing the frontend, who carries no
  `fe_typo_user` at all. See [typo3.md](typo3.md).
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
Joomla hashes it from the site secret; phpBB lets the admin set the prefix. Where
no substring can match, these two presets ship *no* cookie rule and say so — rather
than shipping one that quietly does nothing. The guide then hands you the `map` that
works on your install. Where a stable substring *does* exist, the preset ships it:
MediaWiki's cookie prefix varies (it's the database name), but every install shares
the `Token=` / `_session=` / `UserID=` suffixes, so the preset matches those;
Drupal's `SESS` prefix is fixed, so the preset matches that.

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

**Flarum.** The instructive rejection, because it *looks* shippable and is not.
Flarum has a stable, non-`APP_NAME`-derived cookie prefix (`CookieFactory`, default
`flarum`) and a cookie that means "logged in": `flarum_remember`. The trap is what
happens when a user **doesn't tick "remember me"** — which is the checkbox's
*default* state. `CreateTokenController` branches:

```php
if (Arr::get($body, 'remember')) { $token = RememberAccessToken::generate($user->id); }
else                             { $token = SessionAccessToken::generate($user->id); }
```

and `Rememberer::remember()` — the **only** writer of `flarum_remember` — is called
only for the `RememberAccessToken` branch. So an ordinary logged-in user carries
**only `flarum_session`**, which Flarum starts for every anonymous visitor too.
Both doors are locked:

- bypass `flarum_session` → bypasses **100%** of traffic (hit rate 0)
- bypass only `flarum_remember` → a logged-in user is served a **cached anonymous
  page**

The second is a **leak, not a lost hit**, and it is the *common* path rather than an
edge case. That is the exact inverse of the [`kirby`](kirby.md) / [`wagtail`](wagtail.md)
condition, which fails toward a needless bypass. **When a preset's failure mode
serves one user's page to another, there is no preset.**

> **"But we have cookie VALUE predicates now — doesn't that fix Flarum?" No.**
> Asked and answered against the source; do not re-open it. `StartSession`
> (`src/Http/Middleware/StartSession.php`) sets `flarum_session` on **every**
> response with no actor check, and its value is an opaque Laravel session id —
> byte-shape-identical for a guest and a member. Login state is the `access_token`
> key **inside the server-side session payload** (`AuthenticateWithSession.php`),
> and it never reaches a cookie. There is nothing in any cookie, *name or value*,
> that differs between the two. The value predicate that rescues [phpBB](phpbb.md)
> works because phpBB puts the user id in the cookie; Flarum does not put anything
> there. **Flarum stays rejected.**
>
> **Joomla is the same shape, and its md5 cookie name is a red herring.** Joomla's
> session name is `md5(md5($secret . $session_name))` — per-install, so a fixed-name
> matcher genuinely cannot match it. But solving the *naming* problem would not
> solve the *safety* problem: the session is started **eagerly for every anonymous
> visitor** (`JoomlaStorage::get()` auto-calls `start()`; `WebApplication::
> afterSessionStart()` then writes a **guest** `User` into it), and the guest/member
> bit lives in a **database column** (`#__session.guest`), not in the cookie. So
> even a perfect name match would only find you a cookie that guests also have.
> Being able to *match* a cookie is not the same as being able to *tell users
> apart*. That is why [`joomla`](joomla.md) still carries the ‡ warning.

**Grav, Craft, October, Statamic.** All four die on the cookie, in the two ways this
page keeps repeating. *Guest-issued*: Craft's `CraftSessionId` and October's
`october_session` are perfectly stable literals handed to **every** anonymous
visitor (Craft's own issue tracker: *"the cookie is being set for any user visiting
the site, even if they're not logged in"*). *Per-install*: Grav's session cookie is
`grav-site-<hash>`. Statamic manages **both at once** — `<APP_NAME>_session`, which
is per-install *and* set for every guest. Grav is the painful one: flat-file traffic
is the ideal shape for a page cache, and it still cannot be expressed.

**NodeBB.** Its only session cookie, `express.sid` (config-renameable via
`sessionKey`), is issued to every visitor — guest and member alike — with an
opaque, session-store-backed value carrying no guest/member marker (auth state
lives server-side against Redis/Mongo, not in the cookie). NodeBB's own GitHub
issue #5418, filed by a community member asking for exactly a "logged in"
cookie for this exact reverse-proxy-caching use case, confirms none exists and
none has shipped. The Joomla shape: guest/member bit lives server-side, not in
anything the proxy can read.

**FluxBB.** The value trick that would normally separate guest from member
(phpBB-style: leading pipe-delimited `user_id` field == `1` for guest) works in
principle — but the cookie **name** itself (`$cookie_name`, default
`pun_cookie`) is admin/install-configurable free text with no guaranteed fixed
suffix analogous to phpBB's `_u`. This stacks the Joomla naming-instability
trap on top of an otherwise-workable value trick: a preset keyed to the
default literal name would silently stop matching (fail toward full-bypass,
never a leak, but with no way for an operator to know protection lapsed) on
any install where the name was customized.

**miniBB.** Its one cookie, `miniBBforums`, is also issued to guests via the
anonymous-posting-name feature with an empty password subfield — a phpBB-shape
value split exists in principle, but requires parsing a subfield this module's
cookie-value engine cannot express (same class of limitation as SMF/PunBB,
except those two at least clear the presence-only fallback bar; miniBB's admin
path is also query-arg dispatched with no stable URI-prefix surface to lean on
as compensation). Rejected rather than shipped as a false-confidence partial.

**Forem.** The session cookie name is a fully admin/env-configurable literal
(`ApplicationConfig["SESSION_KEY"]`) with no derivable pattern at all — worse
than Joomla's md5 hash, which is at least a fixed *shape*. The one fixed-name
identity cookie, `forem_user_signed_in`, is only set by the cross-subforem SSO
flow, not by an ordinary Devise login — so it misses the common case entirely
(useless as a sole defensive signal, and not a leak risk only because it's
inert for most logins). Devise's `remember_user_token` is real but opt-in
(remember-me checkbox), which is the Flarum trap: an ordinary login with the
box unticked is indistinguishable from a guest by any cookie. Rejected.

**HumHub.** Yii2's `_identity` (autologin) cookie is only issued when
`duration>0` — i.e. only when "remember me" was ticked. A plain login sets
`duration=0`, so Yii issues only the PHP session cookie, which guests also
receive via any session-touching request (CSRF token issuance, guest search).
No documented second signal distinguishes a plain-login member from a guest.
The Flarum trap, in a new skin: bypassing on `_identity` alone leaks every
non-remember-me session; bypassing on the session cookie zeroes the hit rate.

**Mastodon.** `_mastodon_session` (Rails `ActionDispatch::Session::CookieStore`)
is issued to **every** visitor on **every** request, opaque and rotating, no
guest/member marker (confirmed by mastodon/mastodon#10468 and #23843). The
only persistent-login signal, Devise's `remember_user_token`, is opt-in
(remember-me) — the Flarum trap again. Mastodon's own community nginx configs
that do cache guest traffic bypass on **any** cookie presence at all
(`map $http_cookie $skip_cache_cookie { default 1; "" 0; }`) plus `Authorization`
— i.e. they don't solve this with a named-cookie rule either, they just accept
the same near-zero-hit-rate floor this project rejects a preset for shipping.

**Codoforum.** Closed-source core (no public repo; only third-party SSO
bridges are public). Official docs name an unspecified `rememberMe()` cookie
with no documented name, value, or behavior on an ordinary (non-remember-me)
login — the Flarum trap, unverifiable. Compounded by CodeIgniter's default
session cookie being guest-issued with no accessible source to check for a
value predicate. No public source exists to establish either half of a safe
rule, so this is rejected on evidentiary grounds as much as structural ones.

**WoltLab Suite.** Fails on two independent axes at once. The cookie name
carries a per-installation random hex hash (`wsc_<hash>_user_session`), so no
fixed substring/suffix generalizes across installs — the Joomla naming
problem. And even granting a stable name, WoltLab's own WSC 5.4+ migration
docs describe the session cookie as an opaque signed string set identically
for guests and members, with no documented value split (no phpBB-style `_u=1`
analog) — so a value predicate isn't available either, even per-install.
Closed-source PHP prevents independent verification of either claim.

**The test to apply before asking for a new preset:** *what fraction of this app's
requests are pages a logged-out stranger can see, that look the same for every
logged-out stranger?* If the answer is "basically none", the app does not want a
page cache, and no preset will change that. Note this is **not** about whether the
app is proxied or PHP or Rails — it is only about the anonymous-shared fraction.

**Frameworks fail this test differently: they cannot be *asked* it.** Django,
Laravel, Rails and friends do not have an anonymous-shared fraction — the code
written on top of them does. A framework preset would be guessing about an app we
have never seen, so instead there is [frameworks.md](frameworks.md), which teaches
the derivation rather than shipping a guess.

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
