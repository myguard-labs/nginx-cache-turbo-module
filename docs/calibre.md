# calibre content server + cache-turbo

_Last researched: 2026-11-07 (calibre 9.18.0, `src/calibre/srv`)._

`calibre-server` ships with authentication **off**. In that default the whole
library UI, the OPDS feed, covers and book downloads are anonymous, so a shared
cache is both safe and useful. With authentication **on** the server uses HTTP
Digest or Basic, so every request carries an `Authorization` header, which the
module's storage floor never caches: the preset is then redundant but harmless.

## Preset

```nginx
cache_turbo         ct;
cache_turbo_backend calibre;
```

<!-- markdownlint-disable MD013 -->

| Check | Values |
| --- | --- |
| Cookie substrings | none |
| URI prefixes | `/cdb/`, `/book-set-last-read-position`, `/book-set-annotations`, `/book-get-last-read-position`, `/book-get-annotations`, `/interface-data/init`, `/ajax-setup`, `/kosync/`, `/book-get-storage`, `/book-set-storage` |
| Query args | none |

<!-- markdownlint-enable MD013 -->

There is no session cookie and no API key to match (the only cookie is the
`android_workaround` path cookie on `/get/`, set only with auth on), so the tier
is URI-only:

- `/cdb/` is the write endpoint (needs `local_write` or `trusted_ips`);
- the `/book-set-*` and `/book-get-*` routes carry per-user reading state;
- `/interface-data/init` has an ETag that includes the username;
- `/ajax-setup` is `no-cache, must-revalidate` upstream;
- `/kosync/` is the KOReader sync server: per-user reading progress at a shared
  URL, identified by `X-Auth-User` / `X-Auth-Key` headers rather than
  `Authorization`, and with server auth off any `X-Auth-User` is accepted;
- `/book-get-storage` and `/book-set-storage` are per-user key/value stores.

The slash-less rows are the full route names on purpose. The URI matcher
continues a slash-less needle only at `/` or `.`, so a `/book-set-` stem would
match nothing.

## Where the hits come from

`/static/*`, favicons and `/icon/*` carry `public, max-age=86400`. Most other
responses (index, `/get/`, `/opds`, `/interface-data`) carry **no**
`Cache-Control`, only an ETag, so the module serves them under its own
`cache_turbo_valid` window. Keep that short on a library you edit.

## Subpath

`--url-prefix` moves every route, so set `cache_turbo_backend_prefix` to match.

## Auth off means a public library

Without server authentication anyone who can reach the proxy can read the
library; the cache does not change that, but it also does not add a login.
Put authentication in front of the proxy if the library is not public.
