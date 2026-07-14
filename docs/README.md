# cache-turbo docs

Per-application guides. The [main README](../README.md) is the reference for
every directive; these pages are the *applied* version — a working vhost, the
cookie/key decisions, and the specific ways each application can bite you.

## CMS / application presets

One page per `cache_turbo_backend` preset:

| Preset | Guide | In `generic`/`auto`? | Protects logged-in users out of the box? |
|---|---|---|---|
| `wordpress` | [wordpress.md](wordpress.md) | ✅ yes | ✅ yes (`wordpress_logged_in_*`) |
| `woocommerce` | [woocommerce.md](woocommerce.md) | ✅ yes | ✅ yes — **but must be stacked with `wordpress`** |
| `joomla` | [joomla.md](joomla.md) | ✅ yes | ❌ **no** — you must add a `cache_turbo_bypass` for the session cookie |
| `xenforo` | [xenforo.md](xenforo.md) | ❌ **no** — opt-in only | ✅ yes (`xf_user`, `xf_session_admin`) |
| `discourse` | [discourse.md](discourse.md) | ❌ **no** — opt-in only | ✅ yes (`_t`) — and the origin sends `no-store` anyway |
| `phpbb` | [phpbb.md](phpbb.md) | ❌ **no** — opt-in only | ❌ **no** — you must add a `cache_turbo_bypass`, and it needs a *value* test |
| `drupal` | [drupal.md](drupal.md) | ❌ **no** — opt-in only | ⚠️ via the origin — Drupal sends `Cache-Control: private`; no cookie rule shipped |
| `mediawiki` | [mediawiki.md](mediawiki.md) | ❌ **no** — opt-in only | ✅ yes (`*UserID`, `*UserName`) |

Only `wordpress`, `woocommerce` and `joomla` are in `generic`/`auto`. **Every
preset added since is opt-in and must be named explicitly** — their dynamic URIs
are generic English words (`/login`, `/register`, `/user`, `/admin`, `/node`,
`/session`, `/index.php`) that an unrelated site legitimately serves as cacheable
pages, so folding them into `auto` would punch holes in other sites' caches.

Four rows are load-bearing:

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
