# MediaWiki + cache-turbo

_Last researched: 2026-07-18_

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
- [PHP settings / gotchas](#php-settings--gotchas)

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
| URI prefixes | **none** — see below |
| Query args | `veaction`, `returnto`, and the mutating `action=` values (`edit`, `submit`, `delete`, `protect`, `unprotect`, `purge`, `rollback`, `revert`, `watch`, `unwatch`, `markpatrolled`, `mcrundo`, `mcrrestore`) |
| Cookie header substrings | `Token=`, `_session=`, `UserID=` |

MediaWiki's cookies are `<prefix>UserID`, `<prefix>UserName`, `<prefix>Token` and
`<prefix>_session`, where `<prefix>` is `$wgCookiePrefix` — which **defaults to
`$wgDBname`, the name of your database.** So on a wiki whose DB is `mywiki` the
cookies are `mywikiUserID`, `mywikiUserName`, and so on.

That means there is no shippable *prefix* — but unlike Joomla and phpBB, there is
a shippable **suffix**. The tails are distinctive enough to match on, whatever your
`$wgCookiePrefix` is. No configuration needed. The trailing `=` in each literal is
load-bearing: this tier searches the whole `Cookie` header raw and undelimited
across names *and* values, so the `=` is what keeps `Token=` anchored to the end of
a cookie *name* rather than firing on any value that merely contains `Token`.

**Match what upstream matches.** MediaWiki's own `getVaryCookies()` says it in one
line:

> *"Vary on token and session because those are the real authn determiners. UserID
> and UserName don't matter without those."*

So **`Token=` and `_session=` are the load-bearing pair**, and they are what the
preset ships. `UserID=` is kept as cheap belt-and-braces — `CookieSessionProvider`
clears it for an anonymous user, so it costs nothing.

**`UserName=` is deliberately NOT matched**, and this is the non-obvious one.
`unpersistSession()` **does not clear it on logout** — by design, because it
pre-fills the login form for the next visit. So **every visitor who has ever logged
in keeps sending `<prefix>UserName` forever**, long after they are an ordinary
anonymous reader. Bypassing on it is a permanent hit-rate loss against exactly the
shared, cacheable reader the cache exists for — with **zero** safety gain, because
without a token or a session that cookie authenticates nobody. It used to be in
this preset; removing it is a pure win.

**`_session=` is matched even though anonymous visitors can acquire one** (preview
an edit, pick up a CSRF token). That is the XenForo `xf_session` trade in
miniature, and here it lands on the right side of it: upstream names it a real
authn determiner, and the asymmetry is decisive — a bypassed guest costs you
*hits*, a cached member *leaks*.

This mirrors upstream exactly. MediaWiki's own recommended Varnish VCL bypasses on
a cookie regex of `([sS]ession|Token)=` — precisely *because* the prefix is
unpredictable, and precisely on the two names above.

## What is dynamic is the query arg, not the path

With the default configuration, `/wiki/<Title>` is the **cacheable read path** and
`/index.php?...` is the dynamic entry point. A path-prefix rule can't separate a
cacheable article from an uncacheable `Special:` page — they share the `/wiki/`
prefix, and `Special:` is *localised* (`Spezial:`, `Spécial:`) so it isn't
reliably matchable either. The work happens in the args.

## Why this preset has NO URI rules

It used to have three — `/index.php`, `/load.php`, `/api.php` — and every one of
them was a mistake. They are gone. Do not re-add them.

**`/index.php` is the article read path.** The paragraph above describes a wiki
with short URLs configured. A **stock** MediaWiki has `$wgArticlePath` set to
`/index.php?title=$1` (or `/index.php/$1`) — i.e. on a default install
`/index.php` *is* how every article is read. Bypassing that prefix disabled
caching for essentially the entire wiki, silently, with a healthy-looking config.

**`/load.php` and `/api.php` are among the hottest cacheable objects you have.**
ResourceLoader bundles are versioned by a hash in the query string and are
immutable per hash. Wikimedia's production VCL does not merely cache them, it
*protects* them: the one rule that forces `Cache-Control: private` is scoped to
page URLs only, with an explicit comment and two ticket numbers —

```vcl
// Only apply to pages. Don't steal cachability of api.php, load.php, etc.
// (T102898, T113007)
if (req.url ~ "^/wiki/" || req.url ~ "^/w/index\.php" || req.url ~ "^/\?title=") {
    ...
}
```

Their text frontend has **no path-based pass rule at all**. Identity is handled
entirely by folding the session/`Token` cookies into the cache key. That is
exactly the shape of this preset: **cookies + args + the Cache-Control floor, no
paths.** MediaWiki already sends `private, must-revalidate, max-age=0` to a
logged-in user, and `cache_turbo_backend` implies `cache_turbo_cache_control
honor`, whose store path refuses `private`.

If you think you have found a path MediaWiki cannot cache, find a source that
says so before adding it here.

The preset bypasses on **`veaction`** (VisualEditor — always dynamic),
**`returnto`** (login redirect flow), and the **mutating half of
`ActionFactory::CORE_ACTIONS`**, value by value. It deliberately does **not**
bypass on a blanket `action=`, and that split is a considered decision:

| Arg | Cached? | Why |
|---|---|---|
| `action=edit`, `submit`, `delete`, `protect`, `unprotect`, `purge`, `rollback`, `revert`, `watch`, `unwatch`, `markpatrolled`, `mcrundo`, `mcrrestore` | **bypassed** | the mutating core actions, listed one value at a time |
| `veaction=` | **bypassed** | VisualEditor, always dynamic |
| `action=raw` | **cached** | deterministic wikitext; gadgets and JS fetch it constantly — a hot path |
| `action=history` | **cached** | same for every anonymous reader; changes only on edit |
| `action=view`, `render`, `info`, `credits` | **cached** | the read half of `CORE_ACTIONS` — deterministic and shared |
| `diff=`, `oldid=` | **cached** | a revision diff is a pure function of the revision ids, and `oldid` content is *immutable* |
| `printable=` | **cached** | a presentation variant — put it in the key, not a bypass |

A blanket "presence of `action=` ⇒ bypass" rule is the obvious thing to write and
it is **wrong**: it would throw away `raw`, `history`, `diff` and `oldid`, which
are among the most cacheable and most requested URLs on a busy wiki. That's a
measurable hit-rate loss in exchange for nothing. Listing the mutating values
individually gets the safety without the loss.

**Why the rows exist even though MediaWiki already sends `private`.** It does,
and more reliably than "it marks mutating actions private" suggests:
`OutputPage::$mCdnMaxage` starts at **0**, and core raises it in exactly one
place — `ActionEntryPoint::performAction()`, for a `ViewAction` or an exact match
against the page's purgeable canonical URLs. An `?action=edit` URL is neither, so
it falls through to `sendCacheControl()`'s `no-maxage` branch and gets
`private, must-revalidate, max-age=0`. None of those conditions depends on who is
asking, so it holds for **anonymous** requesters too. But that floor is
switched off by `cache_turbo_cache_control ignore`, and correctness here does not
rest on a floor an operator can remove — the same reasoning the Drupal preset
uses. The rows cost almost nothing: the read path is `/wiki/<Title>` with no
`action` argument at all.

`printable=` needs no special handling to become a proper variant: the module's
**default** key is built from the validated `Host` plus `unparsed_uri` — the
original request line, query string included — so `?printable=yes` already splits
into its own entry.

Do **not** hand-write `cache_turbo_key $uri$is_args$args` here. It is not just
redundant, it is actively wrong on a pretty-URL wiki: the `/wiki/` location
rewrites to `/index.php` before the module runs, so `$uri` is `/index.php` for
every article and the whole wiki collapses onto a single cache entry. Leave the
key alone unless you are adding something the default does not carry.

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
            # No cache_turbo_key: the default (host + unparsed_uri) is the only
            # correct one here. After the rewrite below $uri is /index.php for
            # EVERY article, so a $uri-derived key collapses the whole wiki onto
            # one entry.
            cache_turbo_valid   300s;        # wikis tolerate a longer TTL
            cache_turbo_valid   404 410 1m;
            cache_turbo_preset  balanced;

            # `break` keeps the request in THIS location. Without it the rewrite
            # triggers a fresh location search and every directive above is
            # silently discarded in favour of the `\.php$` block.
            #
            # The captured title MUST be forwarded as `title=`. A bare
            # `rewrite ... /index.php break;` throws the page name away and
            # MediaWiki renders the Main Page for every article -- which the
            # cache then happily stores under each article's own URL, since the
            # key is built from the original request line.
            rewrite ^/wiki/(?<pagename>.*)$ /index.php?title=$pagename&$args break;
            include        fastcgi_params;
            fastcgi_param  SCRIPT_FILENAME $document_root/index.php;
            fastcgi_pass   unix:/run/php/php-fpm.sock;
        }

        location ~ \.php$ {
            cache_turbo         ct;
            cache_turbo_backend mediawiki;
            cache_turbo_valid   60s;

            include        fastcgi_params;
            fastcgi_param  SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_pass   unix:/run/php/php-fpm.sock;
        }

        # ResourceLoader modules are versioned by their own hash in the query
        # string -- long-lived and safe to cache hard.
        location = /load.php {
            cache_turbo         ct;
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
        # `^~` outranks the `~ \.php$` regex, so this block must repeat the
        # FastCGI wiring itself. Without it nginx falls back to the static
        # handler and serves the raw PHP source.
        location ^~ /img_auth.php {
            cache_turbo off;

            include        fastcgi_params;
            fastcgi_param  SCRIPT_FILENAME $document_root/img_auth.php;
            fastcgi_pass   unix:/run/php/php-fpm.sock;
        }

        location = /_cache {
            cache_turbo_admin on;
            allow 127.0.0.1;
            deny  all;
        }
    }
}
```

`/load.php` gets its own block with a long TTL because ResourceLoader URLs carry
a version hash in the query string and are immutable for that hash — they are the
hottest cacheable objects on a wiki, and worth a dedicated `location`. It is a
tuning win, **not** a workaround: the preset does not bypass `/load.php` (it has
no URI rules at all), so you can drop this block and still cache it — you just
inherit the shorter default TTL.

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
- **SUL / CentralAuth wikis are covered — but verify.** On a CentralAuth (Single
  User Login) farm the shared cookies are `centralauth_User`, `centralauth_Token`
  and `centralauth_Session`. `centralauth_Token` carries the substring `Token=`,
  so the preset already bypasses a globally-logged-in reader on that alone.
  `centralauth_Session` is capital-`S` and does **not** match the `_session=`
  substring, which is fine — the token is the real authn determiner and is matched.
  Still confirm your actual cookie names if you customise the CentralAuth cookie
  prefix.
- **Don't add a blanket `action=` bypass.** `action=raw`, `action=history`,
  `action=render`, `action=info`, `diff=` and `oldid=` are deterministic, shared,
  and hot. Bypassing them is a real hit-rate loss and buys nothing — the mutating
  `action=` values are already listed individually.
- **`<prefix>_session` is not an auth cookie.** An anonymous visitor who previews
  an edit gets one. Same trap as XenForo's `xf_session`.
- **Don't set `cache_turbo_cache_control ignore`.** MediaWiki's `private` header is
  a load-bearing part of the safety story here, exactly as with Drupal.
- **Every preset is opt-in.** There is no `generic`/`auto` union — name the
  backends you run. `/index.php` is about as generic as a path gets, so a
  mediawiki rule must never be enabled implicitly.
- **`Special:` pages are not path-matchable.** They share the `/wiki/` prefix with
  articles, and the namespace is localised on non-English wikis. Most are
  uncacheable anyway via `Cache-Control`; if you have a specific one to protect,
  give it its own `cache_turbo_bypass` **and** `cache_turbo_no_store` — a bypass
  skips only the lookup, so on its own the protected page is still stored.
- **`img_auth.php`** serves permission-checked files. Never cache it.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached, regardless of preset.

## PHP settings / gotchas

MediaWiki-specific only. The generic PHP-FPM tuning lives elsewhere; these are the
knobs that change how the wiki interacts with cache-turbo.

- **Built-in CDN support (`$wgUseCdn` + `$wgCdnServers`).** MediaWiki has its own
  reverse-proxy mode. `$wgUseCdn` (default `false`; renamed from `$wgUseSquid` in
  1.34, old name removed in 1.35) makes MediaWiki emit `Cache-Control: s-maxage=<n>`
  on **anonymous** page views — with ESI configured it uses `Surrogate-Control`
  instead. The value is capped by `$wgCdnMaxAge` (default `18000` = 5h) and is
  *dynamic*: it shrinks as the page ages, so a freshly-edited page gets a short
  s-maxage and an old one the full cap. Because `cache_turbo_backend mediawiki`
  implies `cache_turbo_cache_control honor`, the module will **respect that
  s-maxage** as the store TTL for anonymous responses — turning on `$wgUseCdn` is
  the origin-side way to control cache-turbo's freshness per page instead of the
  flat `cache_turbo_valid`. `$wgCdnServersNoPurge` lists proxy IP ranges MediaWiki
  should trust for `X-Forwarded-For` but not purge.
- **Sessions belong in the object cache, not files** (`$wgSessionCacheType`).
  Since 1.27 MediaWiki keeps PHP sessions in its object cache; `$wgSessionCacheType`
  inherits `$wgMainCacheType` unless set. Point it at Redis/Memcached (not the
  default file handler) so a multi-worker or multi-host front end shares session
  state — the cookie names cache-turbo matches (`_session=`, `Token=`) are the
  same regardless, but a file-backed session store will not survive behind more
  than one PHP host.
- **Parser cache (`$wgParserCacheType`).** The rendered-HTML-of-wikitext cache is a
  *distinct* layer that MediaWiki consults inside PHP before cache-turbo ever sees
  the response; it falls back to `$wgMainCacheType`. Leave it on — it is what makes
  a cache-turbo MISS cheap. It is not the same thing as the full-page cache and
  purging one does not purge the other.
- **opcache is not optional.** MediaWiki strongly recommends PHP opcache
  (`opcache.enable=1`). The codebase is large — give it headroom
  (`opcache.memory_consumption` 128–256M, `opcache.interned_strings_buffer` 16+,
  a generous `opcache.max_accelerated_files`). Without it every MISS re-compiles
  thousands of PHP files and the origin is slow enough that the cache masks a
  problem rather than an optimisation.
- **`memory_limit` for parsing and thumbnails.** Large articles, big templates, and
  on-the-fly thumbnail generation (GD/ImageMagick) are memory-hungry; a stock 128M
  is tight for a busy wiki — 256M+ is common. Shell-outs for image work are
  separately bounded by `$wgMaxShellMemory`. A MISS that OOMs stores nothing useful.
- **`max_execution_time` for maintenance/jobs.** CLI maintenance scripts
  (`refreshLinks.php`, `runJobs.php`, `rebuildall`) run without a web time limit,
  but web-triggered work — the job queue drained per request at `$wgJobRunRate`, or
  a `?action=purge` — is bounded by `max_execution_time`. Keep heavy refreshes on
  the CLI/cron path so they do not stall a request the front end is caching.
- **MediaWiki, not cache-turbo, is the purger.** With `$wgUseCdn` on, MediaWiki
  sends an HTTP `PURGE` to every host in `$wgCdnServers` when a page changes
  (sending purges needs the PHP `sockets` extension). Point `$wgCdnServers` at this
  nginx and cache-turbo's `PURGE` handler invalidates the article on edit instead
  of waiting out the TTL — see [Vhost + Redis L2](#vhost--redis-l2). The only thing
  cache-turbo has to provide is a reachable, locked-down `cache_turbo_admin`
  location; MediaWiki drives the invalidation.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/drupal.md`](drupal.md) — the other preset that leans on origin `Cache-Control`
- [`docs/README.md`](README.md) — all presets
