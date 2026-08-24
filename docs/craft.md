# Craft CMS + cache-turbo

_Last researched: 2026-07-26 (Craft CMS 5.10.12, released 2026-07-22)._

**There is no `craft` preset.** Craft's identity cookie name is a runtime MD5
that varies not only per application but per *environment* — the same codebase
emits a different cookie name on dev, staging and production. Its visible cookie,
`CraftSessionId`, is issued broadly to guests and means nothing. And Craft ships a
query argument that renders unpublished private content with **no session cookie
at all**, which a naive cache will happily store under the public URL.

This page gives the derivations, then a vhost that matches the identity cookie by
*shape* rather than by name. Same class of rejection as
[`frameworks.md`](frameworks.md).

## Why there is no preset

**1. `CraftSessionId` is not a login signal.** It is the PHP session name
(configurable via `phpSessionName` in
[`GeneralConfig.php`](https://github.com/craftcms/cms/blob/5.x/src/config/GeneralConfig.php)),
issued broadly to anonymous visitors for CSRF and flash messages. Bypassing on it
costs you most of your hit rate and finds no logged-in user — the
[`csrftoken` mistake](frameworks.md#why-there-is-no-framework-preset) with a
Craft label.

**2. The real identity cookie name cannot be hardcoded.**
[`helpers/App.php`](https://github.com/craftcms/cms/blob/5.x/src/helpers/App.php)
builds the web-user config as:

```php
$stateKeyPrefix = md5('Craft.' . WebUser::class . '.' . Craft::$app->getEnvId());
// identityCookie name = $stateKeyPrefix . '_identity'
```

So the wire name is `<32 hex>_identity`. `getEnvId()` folds in the application id
**and the environment**, so dev, staging and production of one codebase each emit
a *different* 32-hex prefix. There is no literal to ship.

**3. `<hex>_username` is a trap.** The same prefix also produces a
`_username` cookie — the remembered-username convenience value for the login
form. It can **persist after logout**. Treating it as authentication marks
logged-out visitors as logged-in, permanently, on any browser that has ever
signed in. Do not match it.

<!-- markdownlint-disable MD013 -->

| Cookie | Meaning | Use as bypass? |
| --- | --- | --- |
| `CraftSessionId` | PHP session, issued to guests for CSRF/flash | Weak — presence ≠ login |
| `<32 hex>_identity` | **the real login cookie**; prefix is `md5('Craft.' . WebUser::class . '.' . getEnvId())` | **Yes — by shape, not by name** |
| `<32 hex>_username` | remembered username, **survives logout** | **No — never** |
| `CRAFT_CSRF_TOKEN` | CSRF token, guest-issued | No, and never in the cache key |

<!-- markdownlint-enable MD013 -->

**4. The `token` argument is the dangerous one.** `$tokenParam = 'token'` in
[`GeneralConfig.php`](https://github.com/craftcms/cms/blob/5.x/src/config/GeneralConfig.php)
drives Craft's share-a-preview / live-preview mechanism: a request carrying
`?token=…` renders **unpublished or private entries with no session cookie
present**. If it is not bypassed, nginx stores a private draft under what looks
like a public URL and then serves that draft to everyone who requests the URL
without the token. This must be an unconditional bypass; so should the
`x-craft-preview` and `x-craft-live-preview` parameters.

Note that the preview token has **two wire forms**, and covering only the query
one leaves a hole. [`src/web/Request.php`](https://github.com/craftcms/cms/blob/develop/src/web/Request.php)
resolves it as:

```php
return $this->getQueryParam('x-craft-preview')
    ?? $this->getQueryParam('x-craft-live-preview')
    ?? $this->getHeaders()->get('X-Craft-Preview-Token');
```

so a preview request may carry no distinguishing query argument at all and be
identified purely by the `X-Craft-Preview-Token` header. The vhost below matches
both.

**5. Every route literal is renameable.** `/admin` is `cpTrigger` — the Craft
docs actively recommend changing it, and it can be `null` for a headless install.
`/actions` is `actionTrigger`. `loginPath` and `logoutPath` are configurable too.
A preset shipping those literals would be right by luck.

## Reverse-proxy vhost core

```nginx
http {
    cache_turbo_zone name=ct 256m;

    # Match the identity cookie by SHAPE -- the 32-hex prefix is
    # md5('Craft.' . WebUser::class . '.' . getEnvId()) and differs per
    # environment, so it cannot be named. `_username` is deliberately NOT
    # matched: it survives logout and is not authentication.
    map $http_cookie $craft_identity {
        default                                       0;
        "~*(^|;\s*)[0-9a-f]{32}_identity="            1;
        "~*(^|;\s*)CraftSessionId="                   1;
    }

    # Preview / share tokens render UNPUBLISHED content with no cookie at all.
    # Unconditional bypass -- see GeneralConfig.php $tokenParam.
    map $args $craft_preview_arg {
        default                                             0;
        "~*(^|&)(token|x-craft-preview|x-craft-live-preview)=" 1;
    }

    # The preview token has a HEADER form too. web/Request.php resolves it as
    #   getQueryParam('x-craft-preview')
    #     ?? getQueryParam('x-craft-live-preview')
    #     ?? getHeaders()->get('X-Craft-Preview-Token')
    # so an arg-only rule leaves the header path uncovered and a header-form
    # preview request would be cached as if it were public.
    map $http_x_craft_preview_token $craft_preview_hdr {
        default 1;
        ""      0;
    }

    map "$craft_preview_arg$craft_preview_hdr" $craft_preview {
        default 1;
        "00"    0;
    }

    # cpTrigger / actionTrigger / loginPath / logoutPath are ALL configurable.
    # Edit these literals to match your config/general.php.
    map $uri $craft_private_uri {
        default                                 0;
        "~*^/(admin|actions|login|logout)(/|$)" 1;
    }

    map "$craft_identity$craft_preview$craft_private_uri" $craft_private {
        default 1;
        "000"   0;
    }

    upstream craft {
        server unix:/run/php/php8.3-fpm.sock;
    }

    server {
        server_name craft.example.com;
        root /var/www/craft/web;

        location / {
            cache_turbo               ct;

            # No preset applies -- enable the origin backstop by hand.
            cache_turbo_cache_control honor;

            # bypass skips the lookup; no_store also refuses to save it.
            # Bypass alone would still store a previewed draft under the
            # public key -- which is exactly the leak this page is about.
            cache_turbo_bypass        $craft_private;
            cache_turbo_no_store      $craft_private;

            # CRAFT_CSRF_TOKEN is NOT in the key. Keying on it would give one
            # entry per visitor and put authenticated HTML in a shared cache.
            cache_turbo_key           $scheme$host$uri$is_args$args;
            cache_turbo_valid         120s;
            cache_turbo_valid         404 410 1m;
            cache_turbo_preset        conservative;

            try_files $uri $uri/ /index.php?$query_string;
        }

        location ~ \.php$ {
            cache_turbo               ct;
            cache_turbo_cache_control honor;
            cache_turbo_bypass        $craft_private;
            cache_turbo_no_store      $craft_private;

            include        fastcgi_params;
            fastcgi_param  SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_pass   craft;
        }

        # Belt and braces. EDIT THESE if you changed cpTrigger/actionTrigger.
        location ^~ /admin   { cache_turbo off; try_files $uri /index.php?$query_string; }
        location ^~ /actions { cache_turbo off; try_files $uri /index.php?$query_string; }
    }
}
```

## Verify and caveats

```bash
# Public entry: MISS then HIT.
curl -s -o /dev/null -D- https://craft.example.com/blog/hello | grep -i x-cache
curl -s -o /dev/null -D- https://craft.example.com/blog/hello | grep -i x-cache

# Control panel and actions: BYPASS.
curl -s -o /dev/null -D- https://craft.example.com/admin | grep -i x-cache
curl -s -o /dev/null -D- https://craft.example.com/actions/users/login | grep -i x-cache

# THE ONE THAT MATTERS: a preview token must NEVER be cached. Any 32 hex
# chars exercise the identity rule; any token value exercises this one.
curl -s -o /dev/null -D- \
  'https://craft.example.com/blog/draft?token=abc123' | grep -i x-cache
# Anything other than BYPASS here means unpublished content is being stored.

# Identity cookie by shape:
curl -s -o /dev/null -D- \
  -H 'Cookie: 0123456789abcdef0123456789abcdef_identity=x' \
  https://craft.example.com/blog/hello | grep -i x-cache

# And the trap: the remembered-username cookie must NOT bypass -- it survives
# logout, so treating it as auth would zero the hit rate for returning users.
curl -s -o /dev/null -D- \
  -H 'Cookie: 0123456789abcdef0123456789abcdef_username=bob' \
  https://craft.example.com/blog/hello | grep -i x-cache
# Expect a normal MISS/HIT here, not BYPASS.
```

- **`cpTrigger` and `tokenParam` renames require editing this config.** Craft's
  own hardening advice is to change `cpTrigger`; if you followed it, `/admin`
  above matches nothing and your control panel is cacheable. Likewise a custom
  `tokenParam` makes the preview bypass a no-op — and that failure silently
  publishes drafts. Grep `config/general.php` for `cpTrigger`, `actionTrigger`,
  `tokenParam`, `loginPath`, `logoutPath` and reconcile every literal.
- **A headless install may have `cpTrigger => null`.** Then there is no control
  panel on this host and the `/admin` rules are harmless dead weight — but
  `/actions` and `token` still matter.
- **`CraftSessionId` is included in the bypass above as a conservative
  choice.** It is guest-issued, so including it costs hit rate on any page that
  starts a PHP session. If your front end is genuinely session-free for guests,
  drop that line and rely on `_identity` alone — but verify with curl #1 from
  [`frameworks.md`](frameworks.md#deriving-your-own-rule-the-3-curls) first, and
  re-verify after deploys.
- **Never put `CRAFT_CSRF_TOKEN` in the cache key.** One entry per visitor, and
  authenticated HTML in a shared cache. It is guest-issued and worthless as a
  discriminator.
- **Locale comes from site URL patterns, not a cookie.** Craft's multi-site
  locales are URL-based, so `$uri` already separates them. There is no stock
  language or theme cookie to vary on.
- **The `_username` cookie is not authentication.** Bears repeating: it persists
  after logout. The regex above matches only `_identity` for exactly this reason.
- **A regex `map` needs PCRE.** On an nginx built `--without-pcre`, a `~pattern`
  key falls through as a literal: `nginx -t` passes and the identity match never
  fires. Check `nginx -V`.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached regardless of the above.

## Origin failure: stale-if-error

By default this module can serve a stale cached copy when the origin returns 5xx; nginx turns a refused connection into a 502 and a hung one into a 504, so a dead origin is covered. If the response supplies no `stale-if-error`, `cache_turbo_keep_stale` provides the fallback window — it defaults to `24h`, and `cache_turbo_keep_stale off` removes that fallback. An honored response `stale-if-error` takes precedence, while an honored `must-revalidate` forbids stale serving. `cache_turbo_use_stale` selects which statuses count as "down" (default: every 5xx); listing any tokens replaces the default rather than extending it. Nothing was ever cached for a URL ⇒ nothing to serve; `error_page 502 503 504 /maintenance.html` is the final fallback.

```nginx
cache_turbo_keep_stale    2h;
cache_turbo_valid         120s;
```

The copy stays fresh for `120s`; if the origin starts failing after that, the expired copy keeps being served for up to `2h` (`cache_turbo_keep_stale`). Past that window, or with nothing cached at all, `error_page` is the fallback. See the README sections on [which failures count as "the origin is down"](../README.md#which-failures-count-as-the-origin-is-down) and [what outage handling cannot do](../README.md#what-outage-handling-cannot-do).

## See also

- [`docs/README.md`](README.md) — all presets and the apps deliberately rejected
- [`docs/frameworks.md`](frameworks.md) — the same "no preset here either"
  reasoning, plus the 3-curl derivation procedure and the `$cookie_` hyphen trap
- [`docs/grav.md`](grav.md) — the other CMS whose cookie name embeds a runtime
  hash
