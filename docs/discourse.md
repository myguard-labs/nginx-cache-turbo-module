# Discourse + cache-turbo

_Last researched: 2026-07-18_

Caching a Discourse forum. **Start with the honest question:
[do you actually want this?](#do-you-want-this)** Discourse already ships its own
anonymous page cache and already sends correct `Cache-Control` — so this preset
is the thinnest of the four new ones, and on a stock install it may buy you very
little.

- [Do you want this?](#do-you-want-this)
- [The short version](#the-short-version)
- [Which cookies bypass, and which must not](#which-cookies-bypass-and-which-must-not)
- [Vhost](#vhost)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)
- [Runtime settings / gotchas](#runtime-settings--gotchas)

## Do you want this?

Unlike WordPress or phpBB, Discourse is not a naive origin:

- **It has a built-in anonymous page cache** (`Middleware::AnonymousCache`,
  enabled by default in production) that caches anonymous GETs in Redis, keyed on
  the things that actually matter — XHR-ness, `Accept`, scheme, host, URI, theme,
  colour mode, locale, mobile.
- **It sends `Cache-Control: no-store` on authenticated responses**
  (`application_controller.rb`), which cache-turbo's `honor` mode — implied by
  `cache_turbo_backend` — refuses to store.

So the origin is already fast for anonymous traffic and already safe for
authenticated traffic. An edge cache in front of it is a *latency* win (you skip
the Rails stack and the Redis round trip entirely) and a *capacity* win under a
traffic spike, not a correctness fix.

Where it genuinely pays off: a large forum behind a slow link to its origin, a
front page that gets hammered by search-engine and social traffic, or an origin
you want to survive a hug of death. If that's not you, `cache_turbo off` is a
perfectly respectable answer and Discourse will be fine.

If you do want it, the preset is small and correct.

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend discourse;      # implies cache_turbo_cache_control honor
```

## Which cookies bypass, and which must not

| Check | Values |
|---|---|
| URI prefixes | `/admin`, `/session`, `/auth/`, `/login`, `/logout`, `/signup`, `/my/`, `/message-bus/`, `/drafts`, `/presence/`, `/notifications`, `/user_actions` |
| Query args | `api_key`, `api_username` |
| Cookie substrings | `_t=` |

**One cookie bypasses: `_t`.** That is Discourse's auth token
(`lib/auth/default_current_user_provider.rb` — `TOKEN_COOKIE`). It is written
only for an authenticated user and *deleted* for an anonymous one, and it is the
exact test Discourse's own anon cache uses to decide a request is cacheable. If
`_t` is present, someone is logged in.

**`_forum_session` must NOT bypass, and this is the important half.** It is the
Rails session cookie, and Rails hands one to *everybody* — every anonymous
first-time visitor gets a `_forum_session` for the CSRF token and flash messages.
Putting it in a bypass list would drop essentially all guest traffic out of the
cache: hit rate ≈ 0, for zero safety gain. Discourse's own cache deliberately
ignores it, and so does this preset.

(If that sounds familiar it is the same trap as XenForo's `xf_session` — see
[xenforo.md](xenforo.md). "Session" in the name does not mean "logged in".)

**`theme_ids` and `forced_color_mode` are variants, not identities.** They change
how the page renders, but everyone who picked dark mode gets the *same* dark page.
They belong in the **key**, not the bypass:

```nginx
cache_turbo_key $uri$cookie_theme_ids$cookie_forced_color_mode;
```

Bypassing on them would disable caching for every user who ever touched the theme
picker. Keying on them shares the cache among everyone with the same choice, which
is the whole point.

## Vhost

Discourse is usually behind its own reverse proxy already; the block below is the
nginx in front of it.

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    upstream discourse {
        server 127.0.0.1:3000;
        keepalive 32;
    }

    server {
        listen 443 ssl http2;
        server_name forum.example.com;

        location / {
            cache_turbo               ct;
            cache_turbo_backend       discourse;   # implies cache_control honor

            # Theme and colour mode are VARIANTS -- key on them, never bypass.
            cache_turbo_key           $scheme$host$uri$is_args$args$cookie_theme_ids$cookie_forced_color_mode;

            cache_turbo_valid         60s;
            cache_turbo_valid         404 410 1m;
            cache_turbo_preset        balanced;

            # Discourse varies on these; let auto-Vary split the buckets.
            cache_turbo_auto_vary     on;

            proxy_set_header Host              $host;
            proxy_set_header X-Real-IP         $remote_addr;
            proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_pass http://discourse;
        }

        # Long-poll / realtime transport: never cache, and don't buffer it.
        location /message-bus/ {
            cache_turbo off;
            proxy_buffering off;
            proxy_http_version 1.1;
            proxy_pass http://discourse;
        }

        # Fingerprinted assets and uploads.
        location ~ ^/(assets|uploads|images)/ {
            cache_turbo off;
            expires 30d;
            access_log off;
            proxy_pass http://discourse;
        }

        location = /_cache {
            cache_turbo_admin on;
            allow 127.0.0.1;
            deny  all;
        }
    }
}
```

Note `/message-bus/` appears twice on purpose: in the preset (so it is skipped
even if a request reaches the `/` block) and as its own `location` with
`proxy_buffering off` (because it is a long-poll transport that must stream).

## Checking it works

```nginx
add_header X-Cache-Turbo $cache_turbo_status always;
```

```bash
# anonymous topic: MISS then HIT
curl -sI https://forum.example.com/t/some-topic/123 | grep -i x-cache-turbo
curl -sI https://forum.example.com/t/some-topic/123 | grep -i x-cache-turbo  # HIT

# preset URI surfaces: BYPASS
curl -sI https://forum.example.com/admin   | grep -i x-cache-turbo

# public profiles /u/ are NOT bypassed: they are anonymous-identical and cache
curl -s -D- -o /dev/null https://forum.example.com/u/someone | grep -i x-cache-turbo  # MISS then HIT

# THE ONE THAT MATTERS: a logged-in user must be BYPASS.
curl -sI -H 'Cookie: _t=abc123' https://forum.example.com/t/some-topic/123 \
     | grep -i x-cache-turbo    # BYPASS

# THE OTHER ONE THAT MATTERS: a GUEST carrying _forum_session must still be a
# HIT. If this says BYPASS, something added _forum_session to a bypass list and
# your cache is now doing nothing for guest traffic.
curl -sI -H 'Cookie: _forum_session=guestsess' \
     https://forum.example.com/t/some-topic/123 | grep -i x-cache-turbo   # HIT
```

## Gotchas

- **`_forum_session` is not an auth cookie.** Every guest has one. Bypassing on it
  is a performance bug that looks like a safety measure.
- **`_t` can be renamed.** It honours the `DISCOURSE_TOKEN_COOKIE` env var. Stock
  and official-Docker installs use `_t`; if yours was renamed, the preset's cookie
  rule will not match and you must add your own `cache_turbo_bypass`.
- **Every preset is opt-in.** `/login`, `/signup`, `/posts` are generic English
  paths a non-forum site legitimately serves as cacheable pages, so no preset is
  ever enabled implicitly. Name it.
- **Don't set `cache_turbo_cache_control ignore`.** Discourse's `no-store` on
  authenticated responses is a real part of your safety here.
- **Discourse's own anon cache is still running.** That's fine — it makes your
  misses cheap. If you want to see cache-turbo's true miss cost, set
  `DISCOURSE_DISABLE_ANON_CACHE=1` and watch your origin latency, not because you
  should run it that way.
- **The API is a bypass surface.** `?api_key=` / `?api_username=` requests are
  authenticated by query arg, not cookie; the preset bypasses on both.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached, regardless of preset.

## Runtime settings / gotchas

Discourse is a Ruby on Rails application (Ember.js frontend), not PHP — there is
no `php.ini`, no FPM pool, no opcache to tune. The runtime knobs that matter for
caching live in the Rails app server and in Discourse's own dependencies.

- **Discourse's own anonymous cache makes this preset largely redundant.**
  `Middleware::AnonymousCache` caches anonymous GETs in Redis and is on by
  default in production (`Auth::DefaultCurrentUserProvider` decides who is
  anonymous via `has_auth_cookie?`, the `_t` check). The origin is therefore
  already fast for guests. An nginx page cache in front is a latency/capacity
  win, not a correctness one — see [Do you want this?](#do-you-want-this). You
  can disable Discourse's layer with `DISCOURSE_DISABLE_ANON_CACHE=1` (a non-empty
  value) or the `anon_cache_store_threshold` site setting (default 2; `0`
  disables), but only to measure your true miss cost — not as a normal
  configuration.

- **Two anon caches means two poisoning surfaces.** Discourse's own anon cache
  has had a run of cache-poisoning CVEs where a crafted request header served a
  poisoned response to later anonymous visitors
  (e.g. CVE-2025-23023 and the XHR/header-based advisories). Stacking a second
  full-page cache with a broad key re-opens the same class of bug at the edge:
  keep the key tight (scheme, host, URI, and the theme/colour variants — nothing
  attacker-controlled) and keep Discourse patched. The `_t` bypass is what keeps
  logged-in responses out of the shared cache; if it is ever misconfigured
  (renamed cookie, missing bypass) you leak one user's authenticated page to
  everyone. This is the one failure mode worth testing on every deploy.

- **`/message-bus/` must never be cached, and must not be buffered.** MessageBus
  is Discourse's realtime transport (long-poll with chunked transfer encoding
  over HTTP/1.1). It requires `proxy_http_version 1.1` and `proxy_buffering off`
  on that location only — buffering it globally stalls every stream. The vhost
  above already carves it out; keep it out of any `cache_turbo` scope.

- **Unicorn is the default app server; worker count is bounded by RAM.** Discourse
  runs Unicorn (master + N forked workers) under `bin/unicorn`, with the count set
  by `UNICORN_WORKERS` (the official Docker image derives a default from CPU/RAM).
  Each worker is a full copy-on-write Rails process — budget roughly a few hundred
  MB resident per worker — so oversubscribing `UNICORN_WORKERS` on a small box
  swaps rather than scales. Puma is available but remains opt-in/experimental;
  the same "one process per worker, memory-bound" reasoning applies. None of this
  changes the nginx config, but it explains why edge caching helps under a spike:
  it keeps the fixed, RAM-limited worker pool from being the bottleneck.

- **Redis and PostgreSQL are hard dependencies of Discourse itself.** Discourse's
  anon cache, MessageBus backlog, Sidekiq job queue, and rate limits all live in
  *Discourse's* Redis — entirely separate from anything cache-turbo does. Don't
  point Discourse at a shared/evicting Redis to "save memory": eviction there
  corrupts sessions and job state, and it will look like a cache bug at the edge
  when it is not one.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/xenforo.md`](xenforo.md) — the same guest-session trap, different forum
- [`docs/README.md`](README.md) — all presets
