# MediaWiki + cache-turbo

Caching a MediaWiki site. MediaWiki is the odd one out among these presets: its
dynamic surface is in the **query args**, not the path, and its cookie names have
no stable prefix. Both facts shape the preset, and one of them
[changes what you must configure](#the-cookie-prefix-is-your-database-name).

- [The short version](#the-short-version)
- [The cookie prefix is your database name](#the-cookie-prefix-is-your-database-name)
- [What is dynamic is the query arg, not the path](#what-is-dynamic-is-the-query-arg-not-the-path)
- [Vhost](#vhost)
- [Vhost + Redis L2](#vhost--redis-l2)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend mediawiki;      # implies cache_turbo_cache_control honor
```

MediaWiki sends `Cache-Control: private, must-revalidate, max-age=0` to logged-in
users (`Output/OutputPage.php`), which `honor` — implied by `cache_turbo_backend`
— refuses to store. The preset's cookie and arg rules are the request-side half
of the same job.

## The cookie prefix is your database name

| Check | Values |
|---|---|
| URI prefixes | `/index.php`, `/load.php`, `/api.php` |
| Query args | `veaction`, `returnto` |
| Cookie substrings | `UserID=`, `UserName=` |

MediaWiki's cookies are `<prefix>UserID`, `<prefix>UserName`, `<prefix>Token` and
`<prefix>_session`, where `<prefix>` is `$wgCookiePrefix` — which **defaults to
`$wgDBname`, the name of your database.** So on a wiki whose DB is `mywiki` the
cookies are `mywikiUserID`, `mywikiUserName`, and so on.

That means there is no shippable *prefix* — but unlike Joomla and phpBB, there is
a shippable **suffix**. `UserID=` and `UserName=` are distinctive CamelCase tails,
and `CookieSessionProvider.php` sets them only for a logged-in user (it explicitly
*clears* `UserID` when the user is anonymous). So the preset matches on those, and
it works whatever your `$wgCookiePrefix` is. No configuration needed.

Two cookies are deliberately **not** matched:

- **`Token`** — too generic. The matcher searches the whole `Cookie` header, so a
  bare `Token` substring would also fire on any unrelated cookie whose *value*
  happened to contain the word.
- **`<prefix>_session`** — MediaWiki issues one to an *anonymous* visitor who
  merely interacts with the wiki (previews an edit, picks up a CSRF token). It is
  closer to XenForo's `xf_session` than to an auth cookie, and bypassing on it
  would cost hit rate for no safety gain.

This mirrors what upstream does. MediaWiki's own recommended Varnish VCL bypasses
on a cookie regex of `(session|Token)=` precisely *because* the prefix is
unpredictable — and its `getVaryCookies()` notes that `UserID`/`UserName` are the
ones that matter.

## What is dynamic is the query arg, not the path

With the default configuration, `/wiki/<Title>` is the **cacheable read path** and
`/index.php?...` is the dynamic entry point. A path-prefix rule can't separate a
cacheable article from an uncacheable `Special:` page — they share the `/wiki/`
prefix, and `Special:` is *localised* (`Spezial:`, `Spécial:`) so it isn't
reliably matchable either. The work happens in the args.

The preset bypasses on **`veaction`** (VisualEditor — always dynamic) and
**`returnto`** (login redirect flow). It deliberately does **not** bypass on a
blanket `action=`, and that omission is a considered decision:

| Arg | Cached? | Why |
|---|---|---|
| `action=edit`, `submit`, `delete` | **not cached** | dynamic — but MediaWiki already sends `private` on these, and `honor` refuses to store them |
| `veaction=` | **bypassed** | VisualEditor, always dynamic |
| `action=raw` | **cached** | deterministic wikitext; gadgets and JS fetch it constantly — a hot path |
| `action=history` | **cached** | same for every anonymous reader; changes only on edit |
| `diff=`, `oldid=` | **cached** | a revision diff is a pure function of the revision ids, and `oldid` content is *immutable* |
| `printable=` | **cached** | a presentation variant — put it in the key, not a bypass |

A blanket "presence of `action=` ⇒ bypass" rule is the obvious thing to write and
it is **wrong**: it would throw away `raw`, `history`, `diff` and `oldid`, which
are among the most cacheable and most requested URLs on a busy wiki. That's a
measurable hit-rate loss in exchange for nothing, because the genuinely dynamic
`action=` values are already covered by MediaWiki's own `Cache-Control: private`.

If you want `printable=` to be a proper variant rather than a separate entry per
URL, fold it into the key:

```nginx
cache_turbo_key $uri$is_args$args;   # args already in the key -> printable= splits naturally
```

## Vhost

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    server {
        listen 443 ssl http2;
        server_name wiki.example.com;
        root /var/www/mediawiki;
        index index.php;

        # Pretty URLs: /wiki/<Title> is the cacheable read path.
        location /wiki/ {
            cache_turbo         ct;
            cache_turbo_backend mediawiki;   # implies cache_control honor
            cache_turbo_key     $uri$is_args$args;
            cache_turbo_valid   300s;        # wikis tolerate a longer TTL
            cache_turbo_valid   404 410 1m;
            cache_turbo_preset  balanced;

            rewrite ^/wiki/(?<pagename>.*)$ /index.php;
            include        fastcgi_params;
            fastcgi_param  SCRIPT_FILENAME $document_root/index.php;
            fastcgi_pass   unix:/run/php/php-fpm.sock;
        }

        location ~ \.php$ {
            cache_turbo         ct;
            cache_turbo_backend mediawiki;
            cache_turbo_key     $uri$is_args$args;
            cache_turbo_valid   60s;

            include        fastcgi_params;
            fastcgi_param  SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_pass   unix:/run/php/php-fpm.sock;
        }

        # ResourceLoader modules are versioned by their own hash in the query
        # string -- long-lived and safe to cache hard.
        location = /load.php {
            cache_turbo         ct;
            cache_turbo_key     $uri$is_args$args;
            cache_turbo_valid   1h;

            include        fastcgi_params;
            fastcgi_param  SCRIPT_FILENAME $document_root/load.php;
            fastcgi_pass   unix:/run/php/php-fpm.sock;
        }

        location ~ ^/(images|resources|skins)/ {
            cache_turbo off;
            expires 30d;
            access_log off;
        }

        # Deleted/private images are permission-checked -- never cache.
        location ^~ /img_auth.php {
            cache_turbo off;
        }

        location = /_cache {
            cache_turbo_admin on;
            allow 127.0.0.1;
            deny  all;
        }
    }
}
```

Note `/load.php` gets its own block that **overrides** the preset's bypass: the
preset lists `/load.php` as dynamic (it is an entry script), but ResourceLoader
URLs carry a version hash in the query string and are extremely cacheable. A
dedicated `location` with a long TTL is the right call on a busy wiki. Drop that
block if you'd rather keep it simple — you lose a hot cache, not correctness.

## Vhost + Redis L2

In `http`:

```nginx
cache_turbo_redis redis://10.0.0.5:6379/0 prefix=wiki: timeout=250ms
                  keepalive=32 keepalive_timeout=60s;
```

MediaWiki's own object cache (`$wgMainCacheType`) is a different layer, inside
PHP. Leave it on. If you point it at the same Redis, give cache-turbo a different
DB number or `prefix=` so a `?all=1` purge doesn't clear both.

MediaWiki can also actively purge a CDN on edit (`$wgUseCdn` + `$wgCdnServers`),
sending `PURGE` requests for changed pages. cache-turbo implements `PURGE` — point
`$wgCdnServers` at this nginx and set `cache_turbo_admin on` on a locked-down
location, and an edit will invalidate the cached article immediately instead of
waiting out the TTL.

## Checking it works

```nginx
add_header X-Cache-Turbo $cache_turbo_status always;
```

```bash
# anonymous article: MISS then HIT
curl -sI https://wiki.example.com/wiki/Main_Page | grep -i x-cache-turbo
curl -sI https://wiki.example.com/wiki/Main_Page | grep -i x-cache-turbo  # HIT

# the cacheable args must STAY cacheable -- these are hot paths
curl -sI 'https://wiki.example.com/wiki/Main_Page?action=raw'     | grep -i x-cache-turbo
curl -sI 'https://wiki.example.com/wiki/Main_Page?action=history' | grep -i x-cache-turbo
curl -sI 'https://wiki.example.com/wiki/Main_Page?oldid=12345'    | grep -i x-cache-turbo
# all of these should MISS then HIT. If they BYPASS, someone added a blanket
# action= rule and you are leaving a lot of hit rate on the floor.

# VisualEditor: BYPASS
curl -sI 'https://wiki.example.com/wiki/Main_Page?veaction=edit' | grep -i x-cache-turbo

# THE ONE THAT MATTERS: a logged-in user must be BYPASS. Substitute your own
# $wgCookiePrefix (defaults to your DB name).
curl -sI -H 'Cookie: mywikiUserID=42; mywikiUserName=Bob' \
     https://wiki.example.com/wiki/Main_Page | grep -i x-cache-turbo   # BYPASS

# And confirm the origin's own defence is in place.
curl -sI -H 'Cookie: mywikiUserID=42' https://wiki.example.com/wiki/Main_Page \
     | grep -i cache-control
# Cache-Control: private, must-revalidate, max-age=0
```

## Gotchas

- **`$wgCookiePrefix` defaults to your DB name.** The preset matches the
  `UserID=` / `UserName=` suffixes so this Just Works — but if you set
  `$wgCookiePrefix` to something that changes those *suffixes* (you can't, via
  that setting alone) or you run a wiki farm with a shared login domain, check the
  actual cookie names before trusting the preset.
- **Don't add a blanket `action=` bypass.** `action=raw`, `action=history`,
  `diff=` and `oldid=` are deterministic, shared, and hot. Bypassing them is a
  real hit-rate loss and buys nothing — the dynamic `action=` values are already
  covered by MediaWiki's `Cache-Control: private`.
- **`<prefix>_session` is not an auth cookie.** An anonymous visitor who previews
  an edit gets one. Same trap as XenForo's `xf_session`.
- **Don't set `cache_turbo_cache_control ignore`.** MediaWiki's `private` header is
  a load-bearing part of the safety story here, exactly as with Drupal.
- **`mediawiki` is not in `generic`/`auto`.** `/index.php` is about as generic as a
  path gets. Name the preset explicitly.
- **`Special:` pages are not path-matchable.** They share the `/wiki/` prefix with
  articles, and the namespace is localised on non-English wikis. Most are
  uncacheable anyway via `Cache-Control`; if you have a specific one to protect,
  give it its own `cache_turbo_bypass`.
- **`img_auth.php`** serves permission-checked files. Never cache it.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached, regardless of preset.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/drupal.md`](drupal.md) — the other preset that leans on origin `Cache-Control`
- [`docs/README.md`](README.md) — all presets
