# NodeBB + cache-turbo

_Last researched: 2026-07-26 (NodeBB 4.14.2 current)._

**There is no `nodebb` preset.** NodeBB looks like it should get one — it
configures `express-session` with `saveUninitialized: false`, which is exactly the
setting that makes [Wiki.js](wikijs.md) preset-able. But a single expression in
its API controller dirties the session for anonymous humans, so `express.sid` is
issued to guests anyway and cannot mean "logged in". No other core cookie
separates the two states.

This page shows the exact line, then gives a URI-based vhost that caches NodeBB's
public forum surface without a cookie rule. Same class of rejection as
[`frameworks.md`](frameworks.md).

## Why there is no preset

**1. The cookie name is configurable.** The wire name comes from `sessionKey` in
`config.json`, defaulted in
[`src/prestart.js`](https://github.com/NodeBB/NodeBB/blob/master/src/prestart.js)
to `express.sid`. Configurable-but-usually-default is survivable on its own.

**2. Guests get it anyway — the `0 >= 0` bug class.**
[`src/webserver.js`](https://github.com/NodeBB/NodeBB/blob/master/src/webserver.js)
sets `saveUninitialized: false`, so an untouched session is never persisted and
never cookied. But
[`src/controllers/api.js`](https://github.com/NodeBB/NodeBB/blob/master/src/controllers/api.js)
builds the config payload with:

```js
csrf_token: req.uid >= 0 ? generateToken(req) : false,
```

Anonymous visitors are `uid = 0`, and `0 >= 0` is **true**. So `generateToken()`
runs for guests, writes the token into `req.session`, marks it modified — and
`saveUninitialized: false` no longer applies, because the session is no longer
uninitialized. `express.sid` is issued to every anonymous human visitor.

Only `uid === -1` (spiders and bots) is excluded. The practical consequence is
inverted from what you would want: **crawlers see a cookie-free site and human
guests do not.** A `cache_turbo_bypass $cookie_express_sid` would bypass every
human request and serve the cache only to Googlebot.

**3. There is no second cookie to fall back on.** `loggedIn` is a **field in the
JSON body** of the API config response, not a cookie. Do not invent a cookie rule
around it — nginx never sees it.

<!-- markdownlint-disable MD013 -->

| | What a preset needs | What NodeBB gives |
| --- | --- | --- |
| Login cookie name | fixed literal | `express.sid`, overridable via `config.json` `sessionKey` |
| Set for a guest? | no | **yes** — `req.uid >= 0` is true for `uid = 0` (`src/controllers/api.js`) |
| Bot vs human | irrelevant | inverted: only `uid === -1` (spiders) stays cookie-free |
| Login discriminator | cookie presence | `loggedIn` is a **JSON payload field**, invisible to nginx |
| Identity override | none | **`_uid` query arg** (`src/middleware/user.js`) authenticates with no cookie at all |

<!-- markdownlint-enable MD013 -->

**4. The `_uid` argument is a hard requirement, not an optimisation.**
[`src/middleware/user.js`](https://github.com/NodeBB/NodeBB/blob/master/src/middleware/user.js)
implements a master-token identity override via the `_uid` query argument: a
request carrying it is authenticated **as that user with no session cookie
present**. If `_uid` is not an unconditional bypass, a response rendered for an
arbitrary user can be stored under a URL that looks anonymous, and then served to
everyone. Any NodeBB config here must bypass it.

## Reverse-proxy vhost core

```nginx
http {
    cache_turbo_zone name=ct 256m;

    # Private / stateful URI surface. Prefix-anchored; extend for plugins.
    map $uri $nodebb_private_uri {
        default 0;
        "~*^/(admin|api/admin)(/|$)"                                   1;
        "~*^/(login|logout|register|reset|confirm)(/|$)"               1;
        "~*^/api(/|$)"                                                 1;
        "~*^/\+api(/|$)"                                               1;
        "~*^/socket\.io(/|$)"                                          1;
        "~*^/(user|me|flags|unread)(/|$)"                              1;
        "~*^/(post-queue|ip-blacklist|registration-queue)(/|$)"        1;
    }

    # `_uid` is a master-token identity override that works with NO cookie.
    # Unconditional bypass -- see src/middleware/user.js.
    map $arg__uid $nodebb_uid_override {
        default 1;
        ""      0;
    }

    # Anything non-idempotent.
    map $request_method $nodebb_write {
        default 1;
        GET     0;
        HEAD    0;
    }

    map "$nodebb_private_uri$nodebb_uid_override$nodebb_write" $nodebb_private {
        default 1;
        "000"   0;
    }

    upstream nodebb {
        server 127.0.0.1:4567;
        keepalive 32;
    }

    server {
        server_name forum.example.com;

        location / {
            cache_turbo               ct;

            # No preset applies -- enable the origin backstop by hand.
            cache_turbo_cache_control honor;

            # bypass skips the lookup; no_store also refuses to save. A bypass
            # alone would still store the private response under the shared key.
            cache_turbo_bypass        $nodebb_private;
            cache_turbo_no_store      $nodebb_private;

            # DELIBERATELY ABSENT: any rule on express.sid. Guests carry it
            # (csrf_token: req.uid >= 0), so a bypass on it would bypass every
            # human request and cache only for spiders. See above.

            cache_turbo_key           $scheme$host$uri$is_args$args;
            cache_turbo_valid         30s;
            cache_turbo_valid         404 410 1m;
            cache_turbo_preset        conservative;

            proxy_set_header Host              $host;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_http_version 1.1;
            proxy_set_header Upgrade           $http_upgrade;
            proxy_set_header Connection        "upgrade";
            proxy_pass http://nodebb;
        }
    }
}
```

If you cannot accept that a logged-in user may be served a cached guest page (see
the first caveat), the alternative is `cache_turbo_key_cookie express.sid;` — one
cache entry per session. That is correct but the hit rate approaches zero, which
is another way of saying NodeBB is largely uncacheable for logged-in-capable
traffic without a site-side change.

## Verify and caveats

```bash
# Public topic: MISS then HIT.
curl -s -o /dev/null -D- https://forum.example.com/topic/12/hello | grep -i x-cache
curl -s -o /dev/null -D- https://forum.example.com/topic/12/hello | grep -i x-cache

# Private surfaces: must be BYPASS.
curl -s -o /dev/null -D- https://forum.example.com/admin | grep -i x-cache
curl -s -o /dev/null -D- https://forum.example.com/api/config | grep -i x-cache

# THE ONE THAT MATTERS: the identity override must never be cached.
curl -s -o /dev/null -D- 'https://forum.example.com/?_uid=1' | grep -i x-cache
# Anything other than BYPASS here is a full account-content disclosure.

# And the inverse check: a plain guest must NOT be bypassed.
curl -s -o /dev/null -D- https://forum.example.com/ | grep -i x-cache
```

- **A logged-in user on a public topic URL is protected only by `honor`.** nginx
  cannot distinguish them from a guest, because both carry `express.sid`. Check
  whether your NodeBB sends `private`/`no-cache` on authenticated page renders
  (`curl -s -o /dev/null -D- -b jar.txt <topic-url> | grep -i cache-control`). If
  it does not, either accept that logged-in users may briefly see a cached guest
  render of a public page, or switch to `cache_turbo_key_cookie` above.
- **The only real fix is site-side.** A plugin (or a core patch) that issues a
  *distinct* cookie only on successful login gives you the literal a preset would
  have shipped. With that in place, `cache_turbo_bypass` + `cache_turbo_no_store`
  on that cookie name is the correct configuration and this whole page becomes
  unnecessary.
- **`_uid` is not optional.** Keep its bypass unconditional even if you believe
  the master token is unset — the check costs nothing and the failure mode is
  catastrophic.
- **`socket.io` must not be cached.** It is bypassed above, and the vhost also
  carries the `Upgrade`/`Connection` headers NodeBB's websocket transport needs.
- **Plugins add routes.** Any plugin mounting a private page needs a line in
  `$nodebb_private_uri`; nothing here can infer them.
- **Rename-aware:** if `sessionKey` is customised in `config.json`, none of the
  above changes — this config deliberately never names the session cookie.

## Origin failure: stale-if-error

By default this module serves a stale cached copy when the origin returns 5xx; nginx turns a refused connection into a 502 and a hung one into a 504, so a dead origin is covered. Once the cached copy's TTL has expired, `cache_turbo_keep_stale` supplies the grace window — it defaults to `24h`, and `cache_turbo_keep_stale off` removes it so errors surface normally. Most CMS/app stacks emit no `stale-if-error` of their own. `cache_turbo_use_stale` selects which statuses count as "down" (default: every 5xx); naming tokens replaces the default rather than extending it. Nothing was ever cached for a URL ⇒ nothing to serve; `error_page 502 503 504 /maintenance.html` is the nicer failure.

```nginx
cache_turbo_keep_stale    2h;
cache_turbo_valid         30s;
```

The copy stays fresh for `30s`; if the origin starts failing after that, the expired copy keeps being served for up to `2h` (`cache_turbo_keep_stale`). Past that window, or with nothing cached at all, `error_page` is the fallback. See the README sections on [which failures count as "the origin is down"](../README.md#which-failures-count-as-the-origin-is-down) and [what outage handling cannot do](../README.md#what-outage-handling-cannot-do).

## See also

- [`docs/README.md`](README.md) — all presets and the apps deliberately rejected
- [`docs/frameworks.md`](frameworks.md) — the same "no preset here either"
  reasoning; note the Express `saveUninitialized` discussion, which NodeBB gets
  right and then undoes
- [`docs/wikijs.md`](wikijs.md) — the Express app that *does* get a preset,
  because its `saveUninitialized: false` actually holds
