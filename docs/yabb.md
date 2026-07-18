# YaBB + cache-turbo

_Last researched: 2026-07-18_

Caching a YaBB (the Perl forum) board. Per-install randomized cookie *names*,
but a stable prefix survives it, and presence alone is safe regardless.

- [The short version](#the-short-version)
- [The randomized suffix, and why presence is still safe](#the-randomized-suffix-and-why-presence-is-still-safe)
- [Vhost](#vhost)
- [Checking it works](#checking-it-works)
- [Gotchas](#gotchas)
- [Runtime settings / gotchas](#runtime-settings--gotchas)

## The short version

```nginx
cache_turbo         ct;
cache_turbo_backend yabb;
```

## The randomized suffix, and why presence is still safe

YaBB's three session/login cookies — `Y2User-<rand>`, `Y2Pass-<rand>`,
`Y2Sess-<rand>` — get a random per-install numeric suffix generated once by
`Setup.pl`. That is the Joomla-shaped naming problem in miniature, but the
**fixed prefixes** (`Y2User-`, `Y2Pass-`, `Y2Sess-`) survive it, so the rule
matches those substrings.

More importantly: presence is safe regardless of the prefix, because the
single write path — `UpdateCookie("write", ...)` — fires **only** from the
post-login-form-POST success branch in `LogInOut.pl`. Every guest / logged-out
/ failed-login path calls `UpdateCookie("delete")` instead, clearing all three
(or, in guest-language-cookie mode, repurposing only the `Y2Pass-` slot to
hold a plaintext `guestlanguage` string — cosmetic, not an auth artifact).
YaBB also always cookies on login regardless of a remember-me checkbox (the
write always fires; only the expiry varies) — so this has none of the
XenForo/Flarum "ordinary login leaves no cookie" trap either.

YaBB is a single-script CGI app (`YaBB.pl?action=X`), so the dynamic surface
lives in query args, not URI prefixes.

## Vhost

```nginx
load_module modules/ngx_http_cache_turbo_module.so;

http {
    cache_turbo_zone name=ct 256m;

    server {
        listen 443 ssl http2;
        server_name forum.example.com;
        root /var/www/yabb;

        location /cgi-bin/YaBB.pl {
            cache_turbo               ct;
            cache_turbo_backend       yabb;

            cache_turbo_valid         60s;
            cache_turbo_preset        balanced;

            gzip_static off;
            fastcgi_pass unix:/run/fcgiwrap.sock;
            include      fastcgi_params;
        }

        location ~* \.(css|js|png|jpe?g|gif|webp)$ {
            cache_turbo off;
            expires 30d;
            access_log off;
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
# guest thread: MISS then HIT
curl -sI 'https://forum.example.com/cgi-bin/YaBB.pl?num=1' | grep -i x-cache-turbo
curl -sI 'https://forum.example.com/cgi-bin/YaBB.pl?num=1' | grep -i x-cache-turbo  # HIT

# THE ONE THAT MATTERS: a logged-in member must be BYPASS.
curl -sI -H 'Cookie: Y2Sess-42891=abcdef123456' \
     'https://forum.example.com/cgi-bin/YaBB.pl?num=1' | grep -i x-cache-turbo      # BYPASS

# posting/admin/pm actions: BYPASS
curl -sI 'https://forum.example.com/cgi-bin/YaBB.pl?action=post' | grep -i x-cache-turbo
```

## Gotchas

- **A site that hand-renames the `Y2*` cookie vars breaks this preset
  silently** — the ACP config lets an admin edit the three var strings, and a
  full rename away from the `Y2*` convention evades the substring match. Same
  caveat class as any other admin-configurable cookie name in this registry.
- **`Set-Cookie` responses are never stored** and `Authorization` requests are
  never cached, regardless of preset.

## Runtime settings / gotchas

YaBB is Perl/CGI, not PHP — there is no `php.ini`, no OPcache, no FPM pool to
tune. The runtime concerns are different in kind, and a couple of them change
how the preset keys pages.

- **The dynamic surface is a query-string `action=`, so the bypass is
  action-aware, not path-based.** Everything routes through the single
  `YaBB.pl` script and dispatches on the `$action` string
  (`YaBB.pl?action=login`, `?action=post`, `?action=admin`, …); a plain thread
  read is `YaBB.pl?num=<id>` with no `action` at all. There is no per-feature
  URI prefix to `location`-match, so the mutating/authenticated paths —
  `login`/`login2`/`logout`, posting, PMs, and the admin center — must be
  excluded by their `action` value, not by path. YaBB also writes multi-argument
  URLs with `;` as the separator (`YaBB.pl?num=17;action=post`); the preset's
  argument scanner splits on both `;` and `&`, checks every occurrence of a
  name, and percent-decodes before comparing, so those forms classify like the
  plain one. nginx's own `$arg_action` variable does none of that — keep it in
  mind if you hand-write bypass rules. The `yabb` preset already
  keys off this; it is the load-bearing signal for this backend and the reason
  a naïve `location`-prefix rule would wrongly cache POST/admin responses.
  (Confirmed against the `YaBB.pl` dispatch model and `LogInOut.pl`.)
- **The login cookie is the member signal.** A logged-in member always carries
  the `Y2User-*` / `Y2Pass-*` / `Y2Sess-*` triple (the write fires only from
  the `Login2` success branch — see above); guests and logged-out visitors
  carry none. Presence of the prefix is what flips a request to `BYPASS`, so
  member views never serve from cache. (Confirmed against `LogInOut.pl`
  `UpdateCookie("write"|"delete")`.)
- **The admin center is an `action`, and it must bypass.** The admin surface is
  reached as `YaBB.pl?action=admin` (and the sub-actions it links to); it is
  authenticated and must never be stored. Because it is an `action` and not a
  separate script, this is covered by the same action-aware exclusion, not by
  `location`-matching an `/admin/` path that does not exist.
- **CGI is slow per request, which is exactly why nginx-level guest caching pays
  off.** Under plain `fcgiwrap`/CGI, each hit forks a fresh `perl` and re-reads
  the flat-file data — a cold, per-request cost on every guest thread view.
  Serving guest pages straight from the cache zone removes that fork entirely,
  so the value of caching here is higher than on a persistent PHP-FPM backend.
  If the board instead runs under a persistent Perl runtime (FastCGI via
  `FCGI`/`mod_fcgid`, `SpeedyCGI`, or `mod_perl`) the origin is faster but the
  caching win still holds; there is no OPcache-equivalent to warm, so nginx is
  the only real caching layer in front of the forum.

## See also

- [README — CMS backends](../README.md#cms-backends-cache_turbo_backend)
- [`docs/README.md`](README.md) — all presets
