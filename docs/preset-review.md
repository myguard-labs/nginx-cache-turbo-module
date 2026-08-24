# Preset review and deployment checklist

_Registry reviewed: 2026-08-17 at `ddb06b8`._

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
| `joomla` | 1 | 1 | — | — | — | Partial: ordinary frontend login uses an install-specific session cookie. |
| `xenforo` | 4 | 11 | 1 | — | 3 | Safe but `xf_session` can reduce guest hit rate; custom cookie prefixes need local rules. |
| `discourse` | 1 | 12 | 2 | — | — | Safe for the stock `_t` token cookie; a renamed token cookie needs a local rule. |
| `phpbb` | — | 7 | 1 | yes | — | Member `_u != 1` is detected without bypassing every guest session. |
| `drupal` | 1 | 7 | — | — | — | `SESS`/`SSESS` names are covered; the broad substring can reduce hit rate on co-hosted apps. |
| `mediawiki` | 3 | — | 15 | — | — | Query-driven private actions are covered without bypassing all `/index.php` articles. |
| `magento` | — | 12 | — | — | 1 | `X-Magento-Vary` is value-keyed; do not convert it to presence bypass. |
| `ghost` | 2 | 4 | 4 | — | — | Cookieless member and paid-content token arguments are covered. |
| `wagtail` | 1 | 3 | — | — | — | Safe while guests remain session-free; anonymous sessions fail safe by reducing hit rate. |
| `kirby` | 1 | 1 | — | — | — | Safe while guests remain session-free; `csrf()` can make guest pages bypass. |
| `shopware6` | — | 5 | — | — | 1 | `sw-cache-hash` is value-keyed; preserve that contract across Shopware upgrades. |
| `typo3` | 2 | 1 | — | — | — | Unsafe after an unmirrored `FE/cookieName` rename; add local bypass and no-store rules. |
| `invision` | — | 5 | 5 | yes | 3 | Vendor-attested closed-source rules; verify cookies on the deployed release. |
| `smf` | 1 | — | 12 | — | — | Safe but presence-only session matching can bypass guests. |
| `vanilla` | 1 | 4 | — | — | — | Verify the deployed product/version and cookie name empirically. |
| `punbb` | 2 | 9 | — | — | — | Covers stock and legacy prefixes; guest-issued cookies reduce hit rate. |
| `phorum` | 3 | 12 | — | — | 1 | Fixed member cookies and language key are covered. |
| `yabb` | 3 | — | 11 | — | — | Random cookie suffixes are covered by stable prefixes. |
| `mybb` | — | 10 | 10 | yes | 2 | Prefix-independent member predicate plus language/theme value keys. |
| `vbulletin` | — | 7 | — | yes | 1 | Closed-source/version-sensitive; verify current vBulletin cookies before rollout. |
| `textpattern` | 2 | 1 | — | — | — | Add a URI rule when the admin directory is renamed. |
| `bludit` | 3 | 2 | — | — | — | Stock auth and remember-me cookies are covered. |
| `spip` | — | 1 | 2 | yes | — | Prefix-independent session/admin/state suffixes are covered conservatively. |
| `bugzilla` | 2 | 35 | 8 | — | — | Login, token-bearing and administrative entry points are covered. |
| `mantisbt` (`mantis`) | 1 | 32 | — | yes | — | Custom PHP `session.name` needs a local rule. |
| `plone` | 4 | 7 | — | — | — | Auth, Zope session, status and language state are covered; retain origin cache headers. |
| `umbraco` | 10 | 1 | — | — | — | Stock member/back-office cookies are covered; custom schemes need local rules. |
| `dotclear` | 3 | 3 | — | — | — | Custom `DC_SESSION_NAME` and same-host admin paths need local rules. |
| `wikijs` | 3 | 14 | — | — | — | Covers Wiki.js 2.x; treat 3.x as a fresh preset review. |
| `redmine` | 2 | 12 | 1 | — | — | Cookie login and cookieless `?key=` authentication are covered. |
| `flarum` | 1 | 10 | — | — | — | Partial: login without remember-me is indistinguishable from a guest session. |
| `opencart` | — | — | 34 | — | — | Route-driven only; pretty URLs and new controllers require deployment checks. |

<!-- markdownlint-enable MD013 -->

`classicpress` is an alias of `wordpress`; `backdrop` is an alias of `drupal`.
They intentionally share the same registry row. `none` is an inheritance-control
sentinel, not a preset.

## Review result

The registry, runtime-test mirrors and documentation index agree on all 34
preset rows and 37 accepted spellings. The preset unit checks cover every
populated cookie and argument row. No internally inconsistent setting was found.

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
   `vanilla`, `vbulletin`, and Wiki.js 3.x when released).

Run the anonymous/member `curl` probes in the application guide after every
major application upgrade. A private request must never produce `HIT`; an
anonymous request should produce `MISS` then `HIT`. Also test one response that
sets the identity cookie: it must not be stored under the anonymous key.
