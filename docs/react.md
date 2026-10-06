# Next.js / React + cache-turbo

_Last researched: 2026-09-29 (next v16.3.7; next-auth 4.24.15, @auth/core 0.41.3,
better-auth 1.7.6, @supabase/ssr 0.12.7, react-router 8.4.0 / 7.18.4,
gatsby 5.16.1, vite 8.3.1)._

React itself is a UI library and has nothing to cache. What you put behind
nginx is a **React framework**: Next.js, React Router (the former Remix), or a
static build from Gatsby or Vite. Only **Next.js** gets a preset, because it is
the only one that serves two different bodies at the same URL. The others are
covered further down with the rules to write yourself.

- [Preset](#preset)
- [Why Next.js needs a header tier](#why-nextjs-needs-a-header-tier)
- [What gets cached](#what-gets-cached)
- [Sessions and auth libraries](#sessions-and-auth-libraries)
- [Vhost](#vhost)
- [Checking it works](#checking-it-works)
- [Advisories this preset defends against](#advisories-this-preset-defends-against)
- [React Router / Remix](#react-router--remix)
- [Gatsby, Vite and other static builds](#gatsby-vite-and-other-static-builds)
- [Caveats](#caveats)

## Preset

```nginx
cache_turbo         ct;
cache_turbo_backend nextjs;
```

<!-- markdownlint-disable MD013 -->

| Check | Values |
| --- | --- |
| Request headers (presence, any value) | `RSC`, `Next-Router-State-Tree`, `Next-Router-Prefetch`, `Next-Router-Segment-Prefetch`, `Next-Url`, `Next-Action`, `X-Middleware-Prefetch`, `X-Nextjs-Data`, `X-Now-Route-Matches`, `X-Middleware-Subrequest` |
| Cookie substrings | `__prerender_bypass`, `__next_preview_data`, `next-auth.session-token`, `authjs.session-token`, `__session`, `better-auth.session_token`, `-auth-token` |
| URI prefixes | `/api/` |
| Query args | `_rsc` |

<!-- markdownlint-enable MD013 -->

Like every preset it implies `cache_turbo_cache_control honor`, which is what
does most of the work: Next.js marks every dynamically rendered response
`private, no-cache, no-store, max-age=0, must-revalidate`, and `honor` refuses
to store it.

## Why Next.js needs a header tier

The App Router fetches a page in two forms from the **same path**:

- a document navigation gets HTML;
- a client-side navigation or prefetch sends `RSC: 1` and gets the React Server
  Component payload, `Content-Type: text/x-component`.

So Next.js marks every App Router response with

```text
Vary: rsc, next-router-state-tree, next-router-prefetch, next-router-segment-prefetch
```

(plus `next-url` when the app uses interception routes). cache-turbo's
automatic `Vary` handling only keys on a short list of axes it understands
(`Accept-Encoding`, `User-Agent`, `Accept-Language`, `Origin`) and refuses to
store a response that varies on anything else. **Without the preset, no App
Router page is ever cached.** That is the safe failure.

The unsafe fix is `cache_turbo_vary_ignore rsc next-router-state-tree …`. It
makes pages cacheable, and the first visitor whose browser prefetches a page
stores the RSC payload under the page URL. Every later visitor then receives a
screen of serialized React instead of HTML. This is exactly the shared-cache
poisoning in
[GHSA-wfc6-r584-vfw7](https://github.com/advisories/GHSA-wfc6-r584-vfw7).
**Do not use `cache_turbo_vary_ignore` for these names.**

The preset does it differently:

1. **Any request carrying one of the listed headers bypasses the cache** —
   no lookup, no store — whatever the value, even empty. Browsers send none of
   them on a document navigation, so this costs no HTML hits.
2. A response `Vary` token that names one of **those headers** is treated as
   **satisfied**, not ignored. Every request that is looked up or stored lacks
   the header, so every stored and every served copy belongs to the same value
   of that axis — the "absent" value. RFC 9110 § 12.5.5 is met.
3. The capture path re-checks the request it is storing for. Even a store that
   runs ahead of the bypass (`cache_turbo_bypass_stale_uri`) refuses a response
   produced for an `RSC` request.

Anything else in `Vary` keeps its normal meaning: a whitelisted axis is keyed,
an unknown one refuses the store. The satisfied axes apply only to locations
with `cache_turbo_backend nextjs`; every other preset and every preset-free
location still refuses them.

The `_rsc` query arg is the client's cache-busting parameter on every RSC
fetch. Bypassing on it keeps a payload URL out of the cache even if a proxy hop
in front of nginx dropped the `RSC` header.

## What gets cached

| Response | Next.js headers | Result |
| --- | --- | --- |
| Static page (App or Pages Router) | `s-maxage=31536000` | Stored; `honor` takes the TTL from `s-maxage`. Purge on deploy. |
| ISR page (`revalidate = N`) | `s-maxage=N, stale-while-revalidate=…` | Stored for N seconds, then served stale while one request refreshes it. |
| Dynamic page (`cookies()`, `headers()`, `no-store` fetch, …) | `private, no-cache, no-store, …` | Never stored. |
| RSC payload / prefetch | same URL, `RSC: 1` | Bypassed by the header tier, never stored. |
| `/_next/static/*` | `public, max-age=31536000, immutable` | Stored; file names are content-hashed, so no purge is needed. |
| `/_next/image` | `Vary: Accept`, `public, max-age=…` | **Not stored.** `Accept` is not a keyable axis here; Next's own image cache serves it. |
| `/_next/data/<buildId>/*.json` (Pages Router) | as the page | Same rules as the page itself; a different URL from the HTML, so no `Vary` conflict. |
| Server Action (`POST`, `Next-Action`) | `no-store` | Not a cacheable method; the header row is a second guard. |
| Draft / preview mode | `private, no-store` + preview cookies | Bypassed on `__prerender_bypass` / `__next_preview_data`. |
| Route Handlers / API routes under `/api/` | none imposed by Next | Bypassed by the URI row (see [Caveats](#caveats)). |

Next.js always adds the router `Vary` to App Router responses, and to Pages
Router responses only when the request was an RSC request. A Pages Router site
therefore caches without the header tier; the preset still bypasses its
prefetch and data headers (`X-Middleware-Prefetch`, `X-Nextjs-Data`).

## Sessions and auth libraries

Next.js has no session of its own. The authentication library sets the cookie,
and the preset matches the **session** cookie of the common libraries. It never
matches the cookies they hand to signed-out visitors, because that would bypass
every guest.

<!-- markdownlint-disable MD013 -->

| Library | Matched (session) | Deliberately not matched (guest-issued) |
| --- | --- | --- |
| Auth.js v5 | `authjs.session-token` (also `__Secure-` prefix and `.0`/`.1` chunks) | `authjs.csrf-token`, `authjs.callback-url` |
| NextAuth.js v4 | `next-auth.session-token` (same prefix/chunk forms) | `next-auth.csrf-token`, `next-auth.callback-url` |
| Clerk | `__session` | `__client_uat` (set to `0` for signed-out visitors) |
| Better Auth | `better-auth.session_token` (default prefix) | — |
| Supabase (`@supabase/ssr`) | `sb-<project-ref>-auth-token` (and chunks) via `-auth-token` | — |
| Lucia v3 | **not matched** — `auth_session` is too generic | add a local rule |
| iron-session | **not matched** — no default name | add a local rule |

<!-- markdownlint-enable MD013 -->

Cookie rows are substrings of the whole `Cookie` header. If you renamed the
cookie (Auth.js `cookies.sessionToken.name`, a Better Auth prefix, …) or use a
library not listed, add both halves yourself — the bypass alone skips only the
lookup and still stores the logged-in response:

```nginx
cache_turbo_bypass   $cookie_myapp_session;
cache_turbo_no_store $cookie_myapp_session;
```

Reading the session in a Server Component makes the route dynamic, and Next
then sends `no-store`, so `honor` is a real second line of defence on the App
Router. It does not cover a page that is statically generated but personalised
client-side, which is fine: the HTML is the same for everyone.

## Vhost

```nginx
http {
    cache_turbo_zone name=ct 256m;

    upstream nextjs {
        server 127.0.0.1:3000;
        keepalive 32;
    }

    server {
        server_name app.example.com;

        location / {
            cache_turbo         ct;
            cache_turbo_backend nextjs;
            cache_turbo_valid   60s;     # fallback only; honor uses s-maxage

            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_http_version 1.1;
            proxy_pass http://nextjs;
        }
    }
}
```

Keep the default cache key. It includes the query string, which is what keeps
`?page=2` and `?page=3` apart; `_rsc` URLs never reach the key because they
bypass first.

Do not strip or rename any of the router headers in front of nginx. A CDN or
proxy that drops `RSC` but keeps the `_rsc` arg is still covered by the arg
row; one that drops both would make RSC requests look like document requests
to every cache behind it, including Next's own.

## Checking it works

```bash
u=https://app.example.com/blog/hello

# 1. Document requests: the second one must be a HIT.
curl -s -o /dev/null -D- "$u" | grep -Ei '^(vary|x-cache):'
curl -s -o /dev/null -D- "$u" | grep -Ei '^(vary|x-cache):'

# 2. RSC request on the same URL: never a HIT, and must answer text/x-component.
curl -s -o /dev/null -D- -H 'RSC: 1' "$u" | grep -Ei '^(content-type|x-cache):'

# 3. The HTML entry is still HTML afterwards.
curl -s "$u" | head -c 100; echo
```

If step 1 never shows `HIT`, check the `Vary` line: an extra axis your app or
middleware adds (for example `Vary: Cookie`) still refuses the store.

## Advisories this preset defends against

The preset is defence in depth, not a substitute for upgrading Next.js.

<!-- markdownlint-disable MD013 -->

| Advisory | Affected | What the preset does |
| --- | --- | --- |
| [GHSA-wfc6-r584-vfw7](https://github.com/advisories/GHSA-wfc6-r584-vfw7) / CVE-2026-44576 — RSC payload cached as HTML | < 15.5.16, 16.0 – < 16.2.5 | Header tier + `_rsc` arg: RSC responses are never looked up or stored. |
| [GHSA-vfv6-92ff-j949](https://github.com/advisories/GHSA-vfv6-92ff-j949) / CVE-2026-44582 — `_rsc` hash collision | see advisory | Any `_rsc` bypasses, whatever its value. |
| [GHSA-3g8h-86w9-wvmq](https://github.com/advisories/GHSA-3g8h-86w9-wvmq) / CVE-2026-44572 — `x-nextjs-data` on a middleware redirect | see advisory | `X-Nextjs-Data` bypasses. |
| [GHSA-267c-6grr-h53f](https://github.com/advisories/GHSA-267c-6grr-h53f) / CVE-2026-44575 — middleware bypass via segment prefetch | see advisory | `Next-Router-Segment-Prefetch` bypasses, so the result is never shared. |
| [GHSA-r2fc-ccr8-96c4](https://github.com/advisories/GHSA-r2fc-ccr8-96c4) / CVE-2025-49005 — missing `Vary` | 15.3.0 – < 15.3.3 | The header tier does not depend on the origin sending `Vary`. |
| [GHSA-67rr-84xm-4c7r](https://github.com/advisories/GHSA-67rr-84xm-4c7r) / CVE-2025-49826 — poisoning DoS | 15.1.0 – < 15.1.8 | Prefetch and data headers bypass. |
| [GHSA-qpjv-v59x-3qc4](https://github.com/advisories/GHSA-qpjv-v59x-3qc4) / CVE-2025-32421 — pageProps JSON for HTML | see advisory | Data-request headers bypass. |
| [GHSA-gp8f-8m3g-qvj9](https://github.com/advisories/GHSA-gp8f-8m3g-qvj9) / CVE-2024-46982 — `x-now-route-matches` | see advisory | `X-Now-Route-Matches` bypasses. |
| [GHSA-g5qg-72qw-gw5v](https://github.com/advisories/GHSA-g5qg-72qw-gw5v) / CVE-2025-57752 — `/_next/image` key confusion | see advisory | `/_next/image` is never stored (`Vary: Accept`). |
| CVE-2025-29927 — `x-middleware-subrequest` middleware bypass | < 12.3.5, 13 – < 13.5.9, 14 – < 14.2.25, 15 – < 15.2.3 | `X-Middleware-Subrequest` bypasses so a bypassed response is never shared. It does **not** stop the bypass itself — strip that header at the edge on unpatched versions. |

<!-- markdownlint-enable MD013 -->

## React Router / Remix

React Router v7/v8 (framework mode, the former Remix) fetches loader data from
a **different URL** — `/about.data`, `/about/_.data`, `/_root.data` (v7) or
`/_.data` (v8), with an optional `_routes` arg — so there is no `Vary`
conflict and no preset is needed. Its default session cookie is `__session`,
which the `nextjs` preset happens to match, but the name is app-chosen and
there is no fixed admin path, so treat it like a framework
([frameworks.md](frameworks.md)): derive the cookie name and add
`cache_turbo_bypass` + `cache_turbo_no_store` for it.

## Gatsby, Vite and other static builds

A static build has no session and nothing per-user in the HTML. Serve it from
disk; cache-turbo adds little in front of a file. The headers to set:

- **Gatsby** documents HTML, `page-data/*.json`, `app-data.json` and `sw.js`
  as `public, max-age=0, must-revalidate`, and `/static/*` plus hashed JS/CSS
  as `public, max-age=31536000, immutable`.
- **Vite** emits hashed files under `/assets/` and sets no `Cache-Control` of
  its own; mark `/assets/` immutable and the HTML `no-cache`.

## Caveats

- **`/api/` is bypassed as a whole.** Route Handlers and API routes get no
  Next-imposed `Cache-Control` and commonly read a session. A public, cacheable
  API wants its own location without the preset, with its own rules.
- **`-auth-token` over-matches.** Supabase's PKCE code verifier cookie exists
  before login and also contains `-auth-token`, so a visitor mid-login bypasses
  the cache. That costs a hit, never a leak.
- **`__session` is broad.** It is Clerk's session cookie and also React
  Router's default session name. Any cookie containing it bypasses — the safe
  direction.
- **Breaker fallback with `cache_turbo_bypass_stale_uri`.** On such a
  location, an open circuit breaker serves its stored HTML copy before the
  header rows run, so an `RSC: 1` request during an origin outage can receive
  HTML instead of the RSC payload. Nothing wrong is stored, and the Next.js
  client falls back to a full page load on a non-RSC content type. Avoid
  combining the two if that degradation is unacceptable.
- **Interception routes add `next-url` to `Vary`.** It is one of the satisfied
  headers, so those pages still cache.
- **Self-hosted Next.js caches too.** Next's own cache handler also stores ISR
  output. cache-turbo in front is a second tier, so purge it on deploy as well.
