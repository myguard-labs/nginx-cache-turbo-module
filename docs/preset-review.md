# Preset review and deployment checklist

_Implementation reviewed: 2026-09-01 at `3db1ca9`; 38 application presets
re-checked upstream 2026-11-07 (13 original, 12 further, 13 last)._

This page records what was checked across every shipped
`cache_turbo_backend` preset. The per-application guides remain the source for
the exact cookie, URI, argument and value-key literals; this page compares the
shape of every preset and makes the remaining operator obligations explicit.

## What a preset can and cannot prove

A preset classifies a request from data nginx can see before contacting the
origin:

- **cookie substring** — safe for a stable login-cookie name, but a renamed
  cookie stops matching;
- **cookie value predicate** — distinguishes a member cookie from the same
  cookie issued to guests;
- **URI prefix** — protects a stable private route, but not a renamed or
  translated route;
- **query argument** — protects front-controller and cookieless-token routes;
- **key cookie** — puts a shared presentation or commerce segment in the cache
  key instead of disabling caching for that segment.

The module cannot inspect server-side session contents. A preset therefore
cannot safely distinguish an authenticated session when guests and members use
the same opaque cookie. It also cannot discover extension routes, renamed
cookies, translated slugs, custom admin paths or application state stored only
at the origin. Keep `cache_turbo_cache_control honor`, keep the unconditional
`Set-Cookie` storage floor, and add both `cache_turbo_bypass` and
`cache_turbo_no_store` for install-specific identity signals.

## Registry coverage

Counts below are generated from the C registry. A dash means the preset
deliberately has no rule of that kind; it is not an unchecked blank.

<!-- markdownlint-disable MD013 -->

| Preset | Cookie rules | URI rules | Arg rules | Value predicate | Key cookies | Deployment result |
| --- | ---: | ---: | ---: | --- | ---: | --- |
| `wordpress` | 3 | 5 | 2 | — | — | Safe for stock cookie names; password previews, comments and REST are covered. |
| `woocommerce` | 3 | 3 | 1 | — | — | Implies `wordpress`; add translated or renamed cart/account slugs. |
| `joomla` | 1 | 2 | — | — | — | Partial: ordinary frontend login uses an install-specific session cookie. |
| `xenforo` | 4 | 11 | 1 | — | 3 | Safe but `xf_session` can reduce guest hit rate; custom cookie prefixes need local rules. |
| `discourse` | 1 | 12 | 3 | — | — | Safe for the stock `_t` token cookie; a renamed token cookie needs a local rule. |
| `phpbb` | — | 7 | 1 | yes | — | Member `_u != 1` is detected without bypassing every guest session. |
| `drupal` | 1 | 7 | — | — | — | `SESS`/`SSESS` names are covered; the broad substring can reduce hit rate on co-hosted apps. |
| `mediawiki` | 3 | — | 15 | — | — | Query-driven private actions are covered without bypassing all `/index.php` articles. |
| `magento` | — | 12 | — | — | 1 | `X-Magento-Vary` is value-keyed; do not convert it to presence bypass. |
| `ghost` | 3 | 4 | 4 | — | — | Cookieless member and paid-content token arguments are covered. |
| `wagtail` | 1 | 3 | — | — | — | Safe while guests remain session-free; anonymous sessions fail safe by reducing hit rate. |
| `kirby` | 1 | 1 | — | — | — | Safe while guests remain session-free; `csrf()` can make guest pages bypass. |
| `shopware6` | — | 5 | — | yes | 1 | `sw-cache-hash` is value-keyed, except the `not-cacheable` marker, which bypasses; preserve that contract across Shopware upgrades. |
| `typo3` | 3 | 1 | 1 | — | — | Unsafe after an unmirrored `FE/cookieName`, `BE/cookieName` or `BE/entryPoint` change; add local bypass and no-store rules. Workspace-preview key `ADMCMD_prev` is covered as cookie and argument. |
| `invision` | — | 5 | 5 | yes | 3 | Vendor-attested closed-source rules, unverified 2026-11-07; verify cookies on the deployed release. |
| `smf` | 1 | — | 12 | — | — | Safe but presence-only session matching can bypass guests. |
| `vanilla` | 1 | 5 | — | — | — | Legacy self-hosted only; current SaaS `vf_*` login-cookie names are per-site and need local rules. The Bearer-authenticated `/api/` is bypassed. |
| `punbb` | 2 | 9 | — | — | — | Covers stock and legacy prefixes; guest-issued cookies reduce hit rate. |
| `phorum` | 3 | 12 | 1 | — | 1 | Fixed member cookies and language key are covered; set `use_cookies` to "Require cookies" so the session id never travels in the URI. |
| `yabb` | 3 | — | 11 | — | — | Random cookie suffixes are covered by stable prefixes. |
| `mybb` | — | 11 | 10 | yes | 2 | Prefix-independent member predicate plus language/theme value keys. |
| `vbulletin` | — | 7 | — | yes | 2 | Closed-source/version-sensitive. `bb_userid`/`bb_password` exist only after a Remember Me login; non-Remember-Me members need an `imloggedin`-style login flag or a local rule (deployment prerequisite). |
| `textpattern` | 2 | 1 | — | — | — | Add a URI rule when the admin directory is renamed. |
| `bludit` | 3 | 2 | — | — | — | Stock auth and remember-me cookies are covered. |
| `spip` | — | 1 | 2 | yes | — | Prefix-independent session/admin/state suffixes are covered conservatively. |
| `bugzilla` | 2 | 35 | 8 | — | — | Login, token-bearing and administrative entry points are covered. |
| `mantisbt` (`mantis`) | 1 | 32 | 1 | yes | — | Custom PHP `session.name` needs a local rule. |
| `plone` | 5 | 7 | — | — | — | Auth, Zope session, status and language state are covered; retain origin cache headers. |
| `umbraco` | 10 | 1 | — | — | — | Stock member/back-office cookies are covered; custom schemes need local rules. |
| `dotclear` | 3 | 3 | — | — | — | Custom `DC_SESSION_NAME` and same-host admin paths need local rules. |
| `wikijs` | 4 | 19 | — | — | — | Covers Wiki.js 2.x and 3.x (3.1.1). |
| `redmine` | 2 | 12 | 3 | — | — | Cookie login and cookieless `?key=`, `?access_token=`, `?bearer_token=` authentication are covered; plus 1 request-header row (`X-Redmine-API-Key`, presence bypass). |
| `flarum` | 1 | 10 | — | — | 1 | Partial: login without remember-me is indistinguishable from a guest session; rechecked at v2.0.2. Guest `locale` cookie is value-keyed. |
| `opencart` | — | — | 34 | — | 1 | Partial: base controller routes only. `OCSESSID` is identical for guests and members, so retain the application `no-store` policy; overriding it needs an application-exposed login boundary, then a fail-closed local map. The `currency` cookie is value-keyed. |
| `servarr` | 2 | 12 | 2 | — | — | Safety preset for Sonarr, Radarr and Lidarr (aliases `sonarr`, `radarr`, `lidarr`). The apps serve no anonymous HTML; the rows keep the login cookie, `/initialize.json` (API key under the upstream `?h=` public rule) and `/api` out of the cache. External auth needs a local bypass on the proxy SSO cookie. |
| `calibre` | — | 10 | — | — | — | URI-only; there is no session cookie or API key. With server auth on, the `Authorization` floor already bypasses every request. |
| `calibreweb` | 2 | 13 | — | — | — | Alias `calibre-web`. Safe only with anonymous browsing on and no reverse-proxy header login (cookieless auth); `session=` also matches guest search sessions, a lost hit only. |
| `nextjs` | 7 | 1 | 1 | — | — | Plus 10 request-header rows (presence bypass; they also satisfy the matching App Router `Vary` axes). Safe for the default Auth.js/NextAuth, Clerk, Better Auth and Supabase session cookies; renamed cookies, Lucia and iron-session need local rules. `/api/` bypass is conservative. |

<!-- markdownlint-enable MD013 -->

`classicpress` is an alias of `wordpress`; `backdrop` is an alias of `drupal`.
They intentionally share the same registry row. `none` is an inheritance-control
sentinel, not a preset.

## Review result

The registry, runtime-test mirrors and documentation index agree on all 34
preset rows and 37 accepted spellings. The preset unit checks cover every
populated cookie and argument row.

The 2026-11-07 upstream re-check of the 13 original application presets
(wordpress, woocommerce, joomla, xenforo, discourse, phpbb, drupal, mediawiki,
magento, ghost, wagtail, kirby, shopware6) read the cited upstream source of
each release below and changed four presets; the other nine needed no literal
change. XenForo is closed source (its docs were unreachable), so its rows stay
vendor-attested and were not re-verified.

| Preset | Release checked | Result |
| --- | --- | --- |
| `wordpress` | 7.1.4 | No change. |
| `woocommerce` | 11.2.2 | No change. |
| `joomla` | 6.2.0 | Added URI `/api/`: the Web Services application authenticates from the `X-Joomla-Token` header, never a cookie. |
| `xenforo` | closed source | No change; vendor-attested, unverified. |
| `discourse` | v2026.10.0 | Added arg `user_api_key`: read from the query on feed and bookmark paths; arg rows match exact names, so `api_key` does not cover it. |
| `phpbb` | 3.3.19 | No change. |
| `drupal` | 11.4.12 | No change. |
| `mediawiki` | 1.46.2 | No change. |
| `magento` | 2.4.9 | No change. |
| `ghost` | v6.75.0 | Added cookie `ghost-admin-toolbar`: the staff toolbar cookie is the only staff signal on site pages, because the admin session cookie is path-scoped to `/ghost`. |
| `wagtail` | v8.1 (Django 6.1.3) | No change. |
| `kirby` | 5.6.3 | No change. |
| `shopware6` | v6.7.16.0 | Added predicate `sw-cache-hash` equals `not-cacheable` (Shopware's own "bypass the cache" marker); the key cookie stays. |

The same day the next 12 application presets (mantisbt, plone, umbraco,
dotclear, wikijs, redmine, flarum, opencart, servarr, calibre, calibreweb,
nextjs) were re-checked against the cited upstream source and changed in eight
of them; umbraco changed only its comment and guide, and dotclear, servarr,
calibreweb and nextjs needed no literal change.

| Preset | Release checked | Result |
| --- | --- | --- |
| `mantisbt` | 2.28.4 | Added arg `key`: the RSS feeds (`issues_rss.php`, `news_rss.php`) log in from `?username=&key=` with no cookie. |
| `plone` | 6.2.2 (Volto 19.7.0) | Added cookie `auth_token=`: the Volto frontend login cookie, read during server-side rendering. |
| `umbraco` | 18.3.1 | No row change; comment and guide corrected: the Delivery API lives under `/umbraco/delivery/api/` and is bypassed by `/umbraco`. |
| `dotclear` | 2.39.3 | No change. |
| `wikijs` | 3.1.1 and 2.5.315 | Added cookie `wikiSession=` and URIs `/_api/auth`, `/_mcp`, `/_scim`, `/_terminal`, `/_collab` for the 3.x rewrite; every 2.x row is kept. |
| `redmine` | 7.0.3 | Added args `access_token`, `bearer_token` (Doorkeeper defaults) and header `X-Redmine-API-Key` (cookieless API key). |
| `flarum` | v2.0.2 | Added key cookie `locale`: guests render in the language from the unprefixed cookie. |
| `opencart` | 4.1.0.4 | Added key cookie `currency`: 4.x sets it for every visitor; the earlier "not set by 4.x" claim was wrong. |
| `servarr` | Sonarr v4.0.20, Radarr v6.4.4, Lidarr v3.1.6 | No change. |
| `calibre` | v9.18.0 | Added URIs `/kosync/`, `/book-get-storage`, `/book-set-storage`: per-user state at shared URLs (KOReader sync authenticates by `X-Auth-User`, not `Authorization`). |
| `calibreweb` | 0.6.27 | No change. |
| `nextjs` | v16.4.5 | No change. |

The same day the last 13 application presets (typo3, invision, smf, vanilla,
punbb, phorum, yabb, mybb, vbulletin, textpattern, bludit, spip, bugzilla) were
re-checked against the cited upstream source and changed in five of them; the
other eight needed no literal change. Invision and vBulletin are closed source,
so their rows stay vendor-attested; the vBulletin 4 evidence comes from
third-party copies of 4.1.11.

| Preset | Release checked | Result |
| --- | --- | --- |
| `typo3` | v14.3.10 | Added cookie `ADMCMD_prev=` and arg `ADMCMD_prev`: the workspace-preview key renders unpublished content for a visitor with no login cookie. Comment and guide corrected: `BE/cookieName` and `BE/entryPoint` are configurable. |
| `invision` | closed source | No change; vendor-attested, unverified at 2026-11-07. |
| `smf` | 2.1.8 | No change. |
| `vanilla` | knowledge-porter and garden-sites (no release; the former main repository is gone) | Added URI `/api/`: the API v2 authenticates by `Authorization: Bearer`, never a cookie. |
| `punbb` | v1.4.4 (no newer tag) | No change. |
| `phorum` | v6.0.6 | Added arg `phorum_session_v5` (URI authentication while `use_cookies` is below 2). Exact-name matching misses the comma form `?1,2,phorum_session_v5=x`; the guide tells operators to require cookies. |
| `yabb` | 2.5.2 (newest downloadable) | No change; verified at 2.5.2, 2.6 and later unverified. |
| `mybb` | 1.8.41 | Added URI `/task.php` (scheduled-task runner). |
| `vbulletin` | closed source; vB 4.1.11 third-party copies | Key cookie `bb_language` corrected to `bb_languageid` and `bb_userstyleid` added (no `bb_language` cookie exists). Documented: login cookies exist only with Remember Me. |
| `textpattern` | 4.9.2 | No change. |
| `bludit` | 3.22.0 | No change. |
| `spip` | 4.4.30 | No change. |
| `bugzilla` | release-5.3.3 | No change. |

`nextjs` was added after the first review (researched 2026-09-29 against Next.js
16.3.7). Its cookie and argument rows are in the same mirrors; its
request-header tier and `Vary` handling are covered by
`ci/t/presets/nextjs.t`. See [react.md](react.md).

`servarr`, `calibre` and `calibreweb` were added after this review (researched
2026-10-06, see [servarr.md](servarr.md), [calibre.md](calibre.md) and
[calibreweb.md](calibreweb.md)). `spotweb` is documented without a preset
([spotweb.md](spotweb.md)). Their rows are in the same mirrors where a cookie or
argument row exists, and `ci/t/presets/{servarr,calibre,calibreweb}.t` cover each
with a negative control.

The 2026-09-01 online refresh also confirmed that XenForo 2.3.12 and Flarum
2.0.0-rc.8 do not require literal changes. Two material documentation
corrections survived review:

- OpenCart 4.1.0.4 has method-qualified request routes such as
  `checkout/cart.list` that the exact base-controller rows do not match. Its
  global `Cache-Control: no-store` keeps the default safe but prevents useful
  page caching; overriding it requires a fail-closed deployment map.
- `Vanilla=` remains a legacy self-hosted literal, while the current SaaS
  product documents a per-site `vf_*` login-cookie name that cannot be
  represented by one safe stock substring.

That result does **not** turn conditional presets into universal ones. The
remaining deployment checks are concentrated in six classes:

1. discover renamed cookies and admin paths (`joomla`, `typo3`, `umbraco`,
   `dotclear`, and any app with a configurable prefix);
2. verify guest-versus-member session behaviour (`xenforo`, `smf`, `punbb`,
   `wagtail`, `kirby`, `flarum`);
3. enumerate translated, pretty or extension-added routes (`woocommerce`,
   `opencart`, and plugin-heavy installations);
4. retain value-keying for shared variants (`xenforo`, `magento`, `shopware6`,
   `invision`, `phorum`, `mybb`, `vbulletin`);
5. test cookieless authentication paths (`ghost`, `redmine`, `bugzilla`, and
   application APIs);
6. empirically verify closed-source or version-sensitive products (`invision`,
   `vanilla`, and `vbulletin`).

Run the anonymous/member `curl` probes in the application guide after every
major application upgrade. A private request must never produce `HIT`; an
anonymous request should produce `MISS` then `HIT`. Also test one response that
sets the identity cookie: it must not be stored under the anonymous key.
