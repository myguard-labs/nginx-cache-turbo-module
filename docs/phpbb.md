# phpBB + cache-turbo

Caching a phpBB 3.x board. **Read [the warning](#the-preset-ships-no-cookie-rule--read-this)
first** — like the Joomla preset, the phpBB preset does **not** protect logged-in
users on its own, and for a more interesting reason.

- [The short version](#the-short-version)
- [The preset ships no cookie rule — read this](#the-preset-ships-no-cookie-rule--read-this)
- [Finding your cookie prefix](#finding-your-cookie-prefix)
- [Writing the bypass](#writing-the-bypass)
- [Vhost](#vhost)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend phpbb;

# REQUIRED. The preset ships no cookie rule -- see below. Replace phpbb3_ with
# your board's actual cookie name (ACP -> Server Configuration -> Cookie Settings).
map $http_cookie $phpbb_user {
    default                    "";
    "~phpbb3_u=(?!1(;|$))"     "1";   # _u present and NOT the ANONYMOUS id (1)
    "~phpbb3_k=[^;\s]+"        "1";   # persistent-login key, non-empty
}

cache_turbo_bypass   $phpbb_user;
cache_turbo_no_store $phpbb_user;
```

Without that `map`, the preset skips phpBB's `.php` entry scripts and nothing
else — a logged-in member's page is a cache candidate like any other.

## The preset ships no cookie rule — read this

| Check | Values |
|---|---|
| URI prefixes | `/ucp.php`, `/mcp.php`, `/adm/`, `/posting.php`, `/memberlist.php`, `/search.php`, `/report.php` |
| Query args | `sid` |
| Cookie substrings | **— (none)** |

phpBB sets three cookies: `<prefix>_u` (user id), `<prefix>_k` (persistent-login
key) and `<prefix>_sid` (session id). Two separate things make them unshippable
as preset rules, and you need both to see why the row is empty.

**1. The prefix is not stable.** The cookie name is `$config['cookie_name']`,
set in the ACP and *randomised by many installers* — `phpbb3_`, `phpbb3_a1b2c`,
or whatever the admin typed. There is no substring the module could ship that
matches your board and not somebody else's. (Same problem as Joomla, different
cause.)

**2. Even with a known prefix, presence is the wrong test.** This is the part
that surprises people. From `phpbb/session.php`, inside `session_create()`:

```php
if (!$bot)
{
    $this->set_cookie('u',   $this->cookie_data['u'], $cookie_expire);
    $this->set_cookie('k',   $this->cookie_data['k'], $cookie_expire);
    $this->set_cookie('sid', $this->session_id,       $cookie_expire);
}
```

That block is guarded on `$bot` — **not on whether anyone is logged in.** Every
non-bot visitor, including a first-time anonymous reader, walks away with all
three cookies. The guest's `_u` is `1` (phpBB's `ANONYMOUS` user id) and their
`_k` is empty, but the *cookies are there*.

So telling a member from a guest needs a **value** test — `_u != 1`, or `_k`
non-empty. The preset registry matches cookie-name **substrings**: it can ask
"is this cookie present?", never "what is it set to?". A `_sid` or `_u` rule in
the preset would therefore match **every anonymous visitor**, take your hit rate
to approximately zero, *and still* not identify a logged-in one. It would be
worse than useless.

The honest answer is to ship no cookie rule and hand you the value test, which
nginx's `map` can express and the preset cannot.

> **Why not just fix the preset to support values?** Because a per-cookie value
> predicate is a real feature with real syntax, and `map` already does it well.
> If you think the module should grow one, that's a reasonable feature request —
> but a broken rule shipped today is not a down payment on it.

phpBB also does **not** reliably send `Cache-Control: private` on authenticated
views, so unlike Drupal or MediaWiki you cannot fall back on the origin
defending itself. On phpBB the bypass is the whole safety story.

## Finding your cookie prefix

ACP → Server Configuration → Cookie Settings → **Cookie name**. Or straight from
the database:

```sql
SELECT config_value FROM phpbb_config WHERE config_name = 'cookie_name';
```

Or just log in and look:

```bash
curl -sI https://forum.example.com/ucp.php?mode=login | grep -i set-cookie
# Set-Cookie: phpbb3_a1b2c_sid=...; Set-Cookie: phpbb3_a1b2c_u=1; ...
#             ^^^^^^^^^^^^^ your prefix
```

Note the guest response already carries `_u=1` and a `_sid`. That is the whole
point of this page.

## Writing the bypass

Substitute your prefix into both patterns:

```nginx
map $http_cookie $phpbb_user {
    default                "";

    # _u is present and is NOT "1" (ANONYMOUS). The negative lookahead is what
    # separates a member from a guest; a plain "_u=" match would hit both.
    "~phpbb3_u=(?!1(;|$))" "1";

    # persistent "remember me" key, set only for a registered user who ticked it
    "~phpbb3_k=[^;\s]+"    "1";
}
```

`_sid` is deliberately absent from the map too — every guest has one, so matching
it would bypass everybody.

Check the map does what you think before you trust it:

```bash
# guest -> "" (cacheable)
curl -s -o /dev/null -w '%{http_code}\n' -H 'Cookie: phpbb3_sid=x; phpbb3_u=1; phpbb3_k=' \
     https://forum.example.com/viewtopic.php?t=1

# member -> "1" (bypass)
curl -s -o /dev/null -w '%{http_code}\n' -H 'Cookie: phpbb3_sid=x; phpbb3_u=42; phpbb3_k=beef' \
     https://forum.example.com/viewtopic.php?t=1
```

(Add `add_header X-Cache-Turbo $cache_turbo_status always;` and read that header
rather than the status code — see [Checking it works](#checking-it-works).)

## Vhost

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    map $http_cookie $phpbb_user {
        default                "";
        "~phpbb3_u=(?!1(;|$))" "1";
        "~phpbb3_k=[^;\s]+"    "1";
    }

    server {
        listen 443 ssl http2;
        server_name forum.example.com;
        root /var/www/phpbb;
        index index.php;

        location / {
            try_files $uri $uri/ /index.php?$args;
        }

        location ~ \.php$ {
            cache_turbo               ct;
            cache_turbo_backend       phpbb;

            # NOT OPTIONAL. The preset ships no cookie rule (see docs).
            cache_turbo_bypass        $phpbb_user;
            cache_turbo_no_store      $phpbb_user;

            cache_turbo_valid         60s;
            cache_turbo_valid         404 410 1m;
            cache_turbo_preset        balanced;

            include                   fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_pass  unix:/run/php/php-fpm.sock;
        }

        # Board styles / avatars / attachments: static, long-lived.
        location ~* ^/(styles|images|assets)/ {
            cache_turbo off;
            expires 30d;
            access_log off;
        }

        # Never cache attachment downloads -- they are permission-checked per user.
        location = /download/file.php {
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

## Checking it works

```nginx
add_header X-Cache-Turbo $cache_turbo_status always;
```

```bash
# anonymous topic: MISS then HIT
curl -sI https://forum.example.com/viewtopic.php?t=1 | grep -i x-cache-turbo
curl -sI https://forum.example.com/viewtopic.php?t=1 | grep -i x-cache-turbo  # HIT

# UCP / posting / admin: BYPASS (this is what the preset gives you)
curl -sI https://forum.example.com/ucp.php | grep -i x-cache-turbo

# A GUEST carrying the full cookie set must still be a HIT. If this says BYPASS,
# your map is matching _sid or a bare _u= and you have destroyed your hit rate.
curl -sI -H 'Cookie: phpbb3_sid=x; phpbb3_u=1; phpbb3_k=' \
     https://forum.example.com/viewtopic.php?t=1 | grep -i x-cache-turbo   # HIT

# THE ONE THAT MATTERS: a logged-in member must be BYPASS. If this says HIT/MISS,
# your cache_turbo_bypass is wrong and you are one request away from serving a
# member's page -- with their username and unread PM count -- to the public.
curl -sI -H 'Cookie: phpbb3_sid=x; phpbb3_u=42; phpbb3_k=beef' \
     https://forum.example.com/viewtopic.php?t=1 | grep -i x-cache-turbo   # BYPASS
```

Run **both** of those last two against your real prefix before you go live. The
guest check protects your hit rate; the member check protects your users.

## Gotchas

- **The preset does not cover logged-in users.** `cache_turbo_backend phpbb;`
  without the `map` + `cache_turbo_bypass` is not a safe config. This is the one
  real footgun.
- **`_sid` is not an auth cookie.** Neither is a bare `_u=`. Guests have both.
  Bypassing on either is the classic mistake and it costs you the entire cache.
- **Changing the cookie name in the ACP silently breaks your map.** Re-check
  after any ACP cookie change.
- **`?sid=` in URLs.** With `session.force_sid` on, phpBB appends the session id
  to links. The preset bypasses on the `sid` arg — it is both a dynamic marker
  and a cache-key poisoning vector. Leave that rule on.
- **`/download/file.php` is permission-checked.** Attachments in a private forum
  must never be cached; the vhost above turns cache-turbo off for it entirely.
- **phpBB does not send `Cache-Control: private` reliably.** Unlike Drupal and
  MediaWiki, you get no second line of defence from the origin here.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached, regardless of preset. Those floors hold — but note a logged-in
  member browsing normally sends only cookies and gets no `Set-Cookie`, so the
  floor does **not** save you.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/joomla.md`](joomla.md) — the other preset with no cookie rule
- [`docs/README.md`](README.md) — all presets
