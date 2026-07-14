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

Two rows there are load-bearing:

- **`joomla` does not ship a cookie rule.** Joomla's session cookie is named from
  a hash of the site secret, so no shippable substring matches it. The preset
  guards `/administrator/` and nothing else — a logged-in front-end user is *not*
  protected until you add your own bypass. See [joomla.md](joomla.md).
- **`xenforo` is not in `generic`.** Its URIs (`/login`, `/register`, `/contact`,
  `/misc`) are generic enough that folding them into `auto` would punch holes in
  unrelated sites' caches. Name it explicitly. See [xenforo.md](xenforo.md).

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
