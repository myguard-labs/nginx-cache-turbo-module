# Sonarr, Radarr, Lidarr + cache-turbo

_Last researched: 2026-10-06 (Sonarr v5-develop and v4 main, Radarr develop,
Lidarr develop; one shared engine)._

**This is a safety preset, not a hit-rate preset.** The apps serve no anonymous
HTML at all: only `/login`, `/loggedout`, the static `/content/` tree and `/ping`
answer without a login. What a shared cache can still do is hold something it
must not. The preset exists to keep the login cookie, the API surface and the
private routes out of the cache.

## Preset

```nginx
cache_turbo         ct;
cache_turbo_backend servarr;   # or sonarr, radarr, lidarr: the same preset
```

<!-- markdownlint-disable MD013 -->

| Check | Values |
| --- | --- |
| Cookie substrings | `Auth=`, `OIDC=` |
| URI prefixes | `/api`, `/feed`, `/signalr`, `/initialize.json`, `/login`, `/logout`, `/loggedout`, `/logfile`, `/updatelogfile`, `/backup`, `/MediaCover`, `/MediaCoverProxy` |
| Query args | `apikey`, `access_token` |

<!-- markdownlint-enable MD013 -->

`sonarr`, `radarr` and `lidarr` are aliases of `servarr`.

The URI rows of this preset match **without regard to ASCII case**, unlike every
other preset. ASP.NET Core routes `/API/v3/series` and `/Initialize.json` to the
same handlers as the lowercase paths, so a byte-exact row would miss them. The
`cache_turbo_backend_prefix` mount is matched the same way. Query arg names stay
byte-exact.

## The hazard: `?h=` makes the origin say "public"

The upstream cache classifier treats any request carrying an `h` query arg as
cacheable (`Cache-Control: public, max-age=31536000`), and it checks that rule
before the `/api`, `/initialize.json` and `/feed` exclusions. A logged-in browser
that fetches `/initialize.json?h=x` gets a body containing `"apiKey"` with a
year-long public lifetime. A shared cache that honours the origin and keys on the
URL stores it, and the next anonymous request for the same URL receives the key.
The same applies to `/api/v3/*?h=x`, which returns library JSON.

The preset closes this in two independent ways:

- the **cookie** rows bypass every request from a Forms or OIDC login;
- the **URI** rows keep `/initialize.json` and `/api` out of the cache even with
  no cookie at all (External auth, API clients using `X-Api-Key`), in any letter
  case.

`ci/t/presets/servarr.t` TEST 3 pins the `?h=x` shape with no cookie, and TEST 15
the case variants (`/API/...?h=x`, `/Initialize.json?h=x`) with only an
`X-Api-Key` header. Without case folding those are stored: the request carries
no cookie and no `Authorization`, and the origin marks the response `public`.

`h` itself is deliberately **not** a bypass arg. It is the only legitimate hit
source: hashed `js`/`css` under `/content/`.

## Cookies

- `<InstanceName>Auth` is issued after a Forms login. The instance name is
  operator-configurable (default is the app name); the `Auth` suffix is fixed, so
  the substring `Auth=` covers renamed instances. It is never issued to a guest.
- `<InstanceName>OIDC` is the Sonarr v5 OIDC session cookie.

**External authentication.** With `AuthenticationMethod = External` the proxy
authenticates and the app issues no cookie. Add a local bypass on your proxy's
SSO cookie or header:

```nginx
cache_turbo_bypass $cookie_sso_session;
```

Basic auth sends an `Authorization` header, which the storage floor never caches.

## Recommended layout

Cache only the static tree and turn the module off for everything else:

```nginx
location /content/ {
    cache_turbo         ct;
    cache_turbo_backend servarr;
    cache_turbo_valid   1h;
    proxy_pass          http://127.0.0.1:8989;
}

location / {
    cache_turbo off;
    proxy_pass  http://127.0.0.1:8989;
}
```

## UrlBase

With a `UrlBase` (for example `/sonarr`), the URI rows no longer start at byte 0
of the request path. Set the prefix so they are rebased. The value must begin
and end with `/`:

```nginx
cache_turbo_backend_prefix /sonarr/;
```

## Not covered

- API keys sent as `Authorization: Bearer` or `X-Api-Key` carry no cookie; they
  are protected by the `/api` and `/feed` URI rows only.
- The `/api/v1` (Lidarr) and `/api/v5` (Sonarr v5) prefixes sit under `/api`.
- Calendar feeds `/feed/v{1,3,5}/calendar/*.ics` authenticate with `?apikey=`,
  covered by both the `/feed` row and the arg row.
- Releases older than the researched trees are not covered. Sonarr v3 served
  the API key from `/initialize.js`, which the `/initialize.json` row does not
  match; on such an install add `cache_turbo_bypass_uri /initialize.js;` or keep
  the module off outside `/content/`.
