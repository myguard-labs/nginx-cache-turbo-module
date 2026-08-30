/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * CMS auto-classify preset data tables (MAINT-SPLIT). Split out of
 * ngx_http_cache_turbo_module.c: 100% static const data, zero functions.
 *
 * ngx_http_cache_turbo_preset_t and its cookie-predicate struct are defined
 * HERE (inside the FUZZ-EXTRACT block, verbatim as before the split) so the
 * generated fuzz .inc — which does not include any project header, only
 * ci/fuzz/ngx_shim_auto.h — stays self-contained. The identical typedef is
 * ALSO declared in ngx_http_cache_turbo_internal.h purely so module.c (which
 * also includes that header) can see the full type at its
 * `ngx_http_cache_turbo_presets[]` iteration sites. This file needs
 * internal.h too, for the NGX_HTTP_CACHE_TURBO_BACKEND_* bit constants the
 * table rows reference (only BACKEND_NONE lives in the public module.h); it
 * defines NGX_HTTP_CACHE_TURBO_PRESETS_C first so internal.h suppresses its
 * copy of the typedef and of the `extern ngx_http_cache_turbo_presets[]`
 * line -- a definition needs neither in the same TU. Both includes stay
 * OUTSIDE the FUZZ-EXTRACT markers below so the generated .inc never gains
 * an internal.h dependency. Keep the two typedef copies in sync if the
 * layout ever changes.
 *
 * ngx_http_cache_turbo_presets[] has external linkage (declared `extern` in
 * the internal header) because module.c iterates it directly.
 *
 * ci/fuzz/extract_auto_classify.sh slices this file's FUZZ-EXTRACT block
 * together with module.c's, so the preset table stays inside the fuzz
 * target it always was; see that script for the concatenation order.
 */

#define NGX_HTTP_CACHE_TURBO_PRESETS_C

#include "ngx_http_cache_turbo_module.h"
#include "ngx_http_cache_turbo_internal.h"

/* R5-1 (perf-microtier-hitpath): default-hide every symbol this TU defines
 * so a module-internal call becomes a direct call instead of a PLT-indirect
 * one (see ngx_http_cache_turbo_module.h for why this is a per-file pragma
 * rather than a global -fvisibility=hidden CFLAGS addition, and why a
 * header-only pragma does not work). Anything in this file that nginx's
 * dynamic-module loader must resolve by name gets an explicit
 * __attribute__((visibility("default"))) at its definition, overriding this
 * pragma (GCC: an explicit attribute always wins over the pragma). */
#pragma GCC visibility push(hidden)


/* >>> FUZZ-EXTRACT auto-classify BEGIN (ci/fuzz/extract_auto_classify.sh) <<< */
/*
 * Auto-classify preset registry. Each row is one CMS backend: NULL-terminated
 * lists of request-Cookie name substrings, r->uri prefixes, and query args
 * that mark a request as a dynamic surface that must NOT be cached. A query-arg
 * entry is either a bare "name" (presence alone is the signal) or "name=value"
 * (the argument must carry exactly that value) — the single-entry-script forums
 * route every page through one `action`/`do` argument, so for them only the
 * VALUE separates a login from an ordinary read. Adding a
 * backend is one row here — no new code path. A row is active when
 * (clcf->backend_presets & row->bit). `generic` (bare `auto`) is the union of
 * WP/Woo/Joomla, whose cookie/URI namespaces are disjoint, so stacking them
 * cannot collide. A backend with generic-English URIs (xenforo, discourse,
 * drupal, ...) stays out of that union and must be named explicitly. Curated
 * heuristic, not a CMS fingerprint.
 *
 * `cookies` is matched as a SUBSTRING of the request Cookie header — presence
 * only, no value predicate. Two consequences the rows below turn on: a cookie
 * an application also issues to GUESTS can never be a bypass rule (it would
 * match most traffic and take the hit rate to zero), and an application whose
 * cookie NAME is per-install (a hash, or an operator-set prefix) cannot be
 * matched at all. Where either applies the row ships no cookie rule and says
 * so, rather than shipping one that does not work; docs/<app>.md then tells the
 * operator to add their own cache_turbo_bypass.
 */
typedef struct ngx_http_cache_turbo_cookie_pred_s
               ngx_http_cache_turbo_cookie_pred_t;

#define NGX_HTTP_CACHE_TURBO_CVOP_NE        0   /* bypass when value != literal */
#define NGX_HTTP_CACHE_TURBO_CVOP_EQ        1   /* bypass when value == literal */
#define NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY  2   /* bypass when value is non-empty */

struct ngx_http_cache_turbo_cookie_pred_s {
    const char  *name_suffix;  /* cookie NAME must END with this (prefix-agnostic) */
    ngx_uint_t   op;           /* NGX_HTTP_CACHE_TURBO_CVOP_*                       */
    const char  *value;        /* literal compared against, NULL for NONEMPTY       */
};

typedef struct {
    ngx_uint_t           bit;
    const char *const   *cookies;  /* substrings in the request Cookie header */
    const char *const   *uris;     /* r->uri prefixes                         */
    const char *const   *args;     /* "name" (presence) or "name=value"       */

    /* Cookie VALUE predicates (tier 2). NULL for presets that classify on name
     * presence alone. An application that issues the SAME cookie to guests and
     * members, and encodes the difference in the value, is unclassifiable by the
     * `cookies` list above and needs a row here instead. See the predicate
     * engine below for why the name is matched by SUFFIX and why an unparseable
     * cookie fails closed to bypass. */
    const ngx_http_cache_turbo_cookie_pred_t  *cookie_preds;

    /*
     * Cookie VALUE KEYING (tier 3). NULL-terminated list of cookie names whose
     * VALUE is folded into the cache key, so visitors carrying different values
     * get different cache entries instead of bypassing the cache altogether.
     *
     * This is for a cookie that is a SEGMENT FINGERPRINT, not an identity: it
     * marks which shared variant of a page the visitor should see (customer
     * group / currency / store view), and many visitors legitimately share one
     * value. Magento's X-Magento-Vary is the type case, and Magento's own
     * reference Varnish VCL keys on exactly this value (vcl_hash: hash_data of
     * the regsub'd cookie) rather than passing.
     *
     * KEY, never BYPASS, and never PRESENCE. Keying on PRESENCE would collapse
     * every non-default visitor into one bucket and is a cross-user leak; that
     * is a different mistake from keying on the VALUE, and the two must not be
     * confused. Bypassing on presence is safe but throws away the hit rate for
     * every non-default ANONYMOUS visitor (guest in a second currency, second
     * store view), who has no private data at all.
     *
     * A preset that lists a key cookie DEPENDS on the Set-Cookie floor in
     * ngx_http_cache_turbo_response_policy(): a request with no key cookie
     * hashes to the ANONYMOUS entry, and if the response ESTABLISHES the segment
     * (Set-Cookie: <keycookie>=...) then storing that body under the anonymous
     * key poisons it for every anonymous visitor. The floor refuses to store ANY
     * Set-Cookie response, which covers that case exactly. Its only relax,
     * P5-8's cache_turbo_ignore_set_cookie, is hard-vetoed for any location
     * with an active backend preset -- that IS the preset-level veto this
     * comment used to demand. DO NOT weaken it.
     */
    const char *const  *key_cookies;
} ngx_http_cache_turbo_preset_t;

/*
 * WordPress. The cookie tier is the load-bearing one: wordpress_logged_in_ is
 * the login cookie, wp-postpass_ unlocks a password-protected post, and
 * comment_author_ marks a commenter who must see their own pending comment.
 * All three are matched as PREFIXES because the wire names carry a site-hash
 * suffix (wordpress_logged_in_<sitehash>) — which is also why the
 * `$cookie_wordpress_logged_in_` form seen in a lot of third-party configs is a
 * permanent no-op: nginx's $cookie_NAME is an EXACT lookup.
 *
 * `preview` renders an UNPUBLISHED revision for an author who holds a valid
 * nonce, so it must never be stored.
 *
 * `rest_route` IS THE REST API, and listing /wp-json/ without it covered only
 * half the surface. The two are not a path and a fallback — the path is sugar
 * over the argument. wp-includes/rest-api.php registers
 *
 *     add_rewrite_rule( '^' . rest_get_url_prefix() . '/(.*)?',
 *                       'index.php?rest_route=/$matches[1]', 'top' );
 *
 * so /wp-json/wp/v2/users/me is REWRITTEN to index.php?rest_route=/wp/v2/users/me,
 * and rest_api_loaded() dispatches only when that query var is set:
 *
 *     if ( empty( $GLOBALS['wp']->query_vars['rest_route'] ) ) { return; }
 *
 * With plain permalinks — or from any client that calls get_rest_url() while
 * they are off, which emits the add_query_arg( 'rest_route', ... ) form — the
 * request never has a /wp-json/ path at all. The URI rule saw nothing and
 * `GET /?rest_route=/wp/v2/users/me` was cacheable. This is the same surface
 * addressed two ways with only one way guarded: a parser differential, not a
 * missing corner case.
 *
 * Matched as a bare NAME, so the whole REST API bypasses, public endpoints
 * included. That is deliberate and matches how /wp-json/ is already treated
 * (docs/wordpress.md calls the wholesale bypass out as a known hit-rate cost).
 * An operator who wants a public endpoint cached gives it its own location.
 *
 * `s` — SITE SEARCH — IS DELIBERATELY ABSENT, and it used to be here. Every
 * logged-out visitor searching "foo" gets the same page: search results are
 * dynamic but ANONYMOUS-IDENTICAL, which is shared, hot, and exactly what a
 * cache is for. A logged-in editor whose results include drafts and private
 * posts is already bypassed by wordpress_logged_in_ on the cookie tier, so the
 * arg rule bought no safety at all — only hit-rate loss.
 *
 * It was also actively harmful. A bypass returns NGX_DECLINED BEFORE the
 * single-flight lock, so miss-collapsing does not apply to a bypassed request:
 * with `s` listed, a flood of `?s=<anything>` put 100% of its load on the
 * origin, uncollapsed, on the single most expensive query WordPress runs (a
 * full-text LIKE scan of wp_posts). Caching search at least collapses repeats.
 *
 * The objection to caching it is unbounded keyspace — `?s=<random>` mints a new
 * entry each time and can LRU-evict the zone. That objection is real, and it
 * has a directive: `cache_turbo_min_uses N` stores an entry only after N
 * misses, so a flood of once-seen search terms never mints one while the terms
 * real visitors repeat still cache. That is the control to reach for, and it is
 * strictly better than the arg rule was — it bounds cardinality WITHOUT handing
 * the origin an uncollapsed flood.
 *
 * It is also not specific to search: the default key includes unparsed_uri, so
 * EVERY query-bearing URL has the same shape. Singling out search did not close
 * that hole; it just moved the cost onto the database.
 *
 * This now matches ct_wagtail_* (/search/ deliberately absent, same reasoning)
 * and the mediawiki registry's refusal of a blanket action= rule. Those two
 * comments argue this case at length; the WordPress row was the outlier and it
 * carried no comment explaining why.
 */
static const char *const  ct_wp_cookies[] = {
    "wordpress_logged_in_", "wp-postpass_", "comment_author_", NULL };
static const char *const  ct_wp_uris[] = {
    "/wp-admin/", "/wp-login.php", "/wp-cron.php", "/xmlrpc.php",
    "/wp-json/", NULL };
static const char *const  ct_wp_args[] = { "preview", "rest_route", NULL };

static const char *const  ct_woo_cookies[] = {
    "woocommerce_items_in_cart", "woocommerce_cart_hash",
    "wp_woocommerce_session_", NULL };
/*
 * THESE THREE SLUGS ARE ENGLISH DEFAULTS, NOT CONSTANTS, and on a non-English
 * store they match NOTHING. WC_Install::create_pages() declares them as
 * TRANSLATABLE strings — _x( 'cart', 'Page slug', 'woocommerce' ) — and wraps
 * the whole page-creation block in wc_switch_to_site_locale() precisely so that
 * "pages are created in the correct language". So a German store gets
 * /warenkorb, /kasse, /mein-konto AT INSTALL TIME, by design. This is not admin
 * drift that a careful operator avoids; it is the shipped behaviour for every
 * locale but one. An admin can also rename the pages afterwards, and the
 * `woocommerce_create_pages` filter can replace the set outright.
 *
 * So DO NOT TREAT THE URI TIER AS THE GUARD HERE. It is a convenience for the
 * default-locale majority. What actually holds on a translated store is the
 * cookie tier above plus the STACKED wordpress preset — a logged-in customer
 * carries wordpress_logged_in_, and a shopper with a cart carries
 * woocommerce_items_in_cart / wp_woocommerce_session_.
 *
 * That stacking is not optional, and this is the case that proves it: a
 * `cache_turbo_backend woocommerce;` used ALONE on a translated store serves a
 * logged-in customer with an EMPTY cart — no woo cookie, no URI match, no
 * wordpress preset — a CACHED /mein-konto. Every WooCommerce doc says to stack
 * `wordpress woocommerce`; this is why.
 *
 * Locale slugs are deliberately NOT enumerated here. The set is unbounded (one
 * per WooCommerce translation, plus whatever the operator typed), so an
 * operator on a translated store adds their own:
 *     cache_turbo_bypass_uri /warenkorb /kasse /mein-konto;
 * See docs/woocommerce.md.
 */
static const char *const  ct_woo_uris[] = {
    "/cart", "/checkout", "/my-account", NULL };
/*
 * wc-ajax is LOAD-BEARING, not decoration — it is the one WooCommerce rule that
 * no URI prefix can substitute for. WC's AJAX endpoints do not live under a path
 * of their own: they ride on WHATEVER page the shopper is on, as a query arg
 * (includes/class-wc-ajax.php::get_endpoint() -> "currentpageurl?wc-ajax=name").
 * So `/?wc-ajax=get_refreshed_fragments` is a request to the CACHED HOME PAGE,
 * and none of /cart, /checkout, /my-account match it.
 *
 * The response is that shopper's cart-fragment HTML. Store it and the next
 * visitor is served someone else's cart. This is the only cross-customer leak
 * path the URI rules cannot close, which is why it is an ARG rule.
 */
static const char *const  ct_woo_args[] = { "wc-ajax", NULL };

/*
 * Joomla. One cookie, and it is a PARTIAL guard — read the caveat.
 *
 * `joomla_remember_me_` is a real fixed prefix ('joomla_remember_me_' .
 * UserHelper::getShortHashedUserAgent()), set only for an authenticated user and
 * cleared on logout. The per-install part is the SUFFIX, so the prefix is
 * matchable — this is the one Joomla cookie that passes both tests.
 *
 * WHAT IT DOES NOT COVER, and this is the important half: it is only present for
 * users who ticked "Remember Me". A normally-logged-in frontend user carries only
 * the SESSION cookie, whose NAME is md5($secret . $session_name) — a per-install
 * hash with no fixed substring anywhere in it. That user is invisible to this
 * matcher. So joomla_remember_me_ raises the floor; it does not make the preset
 * safe on its own.
 *
 * The real guard for a logged-in Joomla user therefore remains Joomla's own
 * Cache-Control (core's page cache plugin itself gates on
 * !$app->getIdentity()->guest), plus the /administrator/ URI rule. An operator
 * running a site with frontend logins MUST add their own cache_turbo_bypass on
 * their install's session-cookie name — docs/joomla.md shows how to find it.
 * Do not read the presence of a cookie rule here as "joomla is now handled".
 */
static const char *const  ct_joomla_cookies[] = { "joomla_remember_me_", NULL };
static const char *const  ct_joomla_uris[] = { "/administrator/", NULL };
static const char *const  ct_joomla_args[] = { NULL };

/*
 * XenForo (XF2). READ THIS BEFORE TOUCHING THE COOKIE LIST.
 *
 * STOCK XF2 HAS NO LOGIN-ONLY COOKIE. This is the central, awkward fact about
 * this preset, and an earlier version of it got this wrong and LEAKED.
 *
 * The trap: `xf_user` looks like the login cookie. It is not — it is the
 * REMEMBER-ME cookie. ControllerPlugin/Login.php calls completeLogin($user,
 * $remember) and only mints `xf_user` inside `if ($remember)`. "Stay logged in"
 * is UNTICKED BY DEFAULT, so an ordinary member who just types their password
 * carries NO xf_user at all. Matching only xf_user + xf_session_admin therefore
 * misses the common login entirely: that member's authenticated page matched no
 * bypass rule, got stored, and was served to strangers.
 *
 * So `xf_session` is in the list, and it has to be, even though XF issues it to
 * guests. That is the whole trade:
 *
 *   - XF2's session IS lazy (Pub/App.php only saves when hasData() is true), so
 *     a clean first-time guest who stores nothing gets NO cookie and still
 *     caches. This is why the rule is not an instant hit-rate zero.
 *   - BUT guests acquire a session routinely: LOGGING OUT writes userId=0 into
 *     the session, a pending 2FA login writes tfaLoginUserId, captcha and spam
 *     state write too. Any of those, and that guest is uncacheable from then on.
 *
 * Net: correct, with an unpredictable and possibly poor hit rate. That is the
 * only cookie-only option that is not a leak. Do not "optimise" xf_session back
 * out of this list — that is the leak, and it is how this preset shipped before.
 *
 * `xf_lscxf_logged_in` is the LiteSpeed XF2 plugin's cookie (its Login.php
 * override sets it IGNORING $remember, with the verbatim comment "Set custom
 * cookie to better track logged in state when 'Stay logged in' is unchecked").
 * A vendor writing PHP to create this cookie is the proof that stock XF has
 * none. On a forum running that plugin it is the precise login signal, and the
 * operator can then narrow the preset by dropping xf_session with their own
 * config. Harmless when the plugin is absent (the cookie simply never appears).
 * The DigitalPoint Cloudflare app sets an equivalent <prefix>logged_in cookie
 * (xf_logged_in on the stock prefix) for the same purpose; an operator running
 * that instead can add it to their own bypass the same way.
 *
 * PRESENTATION VARIANTS ARE KEY COOKIES, NOT BYPASS (tier 3). These are shared
 * across everyone who picked the same value, so folding the VALUE into the key
 * gives one cache entry per variant instead of dropping the visitor from cache
 * (bypassing on them would zero caching for anyone on a dark theme):
 *   - xf_style_id       — selected style on a MULTI-STYLE board. This is the one
 *                         LiteSpeed's own addon varies on (E=...,xf_style_id,...).
 *   - xf_style_variation — light/dark/system VARIATION within a style. NEW in XF
 *                         2.3's dark mode; set client-side by JS when the visitor
 *                         picks a scheme. Distinct cookie from xf_style_id — a 2.3
 *                         board with dark mode needs BOTH keyed.
 *   - xf_language_id    — selected language on a multi-language board.
 * A single-style, single-language, no-dark-mode board shares one value for each
 * and loses nothing by keying on them (one bucket). xf_consent (guest-set, and
 * it DOES change embed HTML: XF renders a consent placeholder in place of a
 * third-party embed until accepted) is deliberately NOT keyed here — it would
 * fragment the cache two ways on every embed-bearing page. docs/xenforo.md tells
 * an operator who needs it to add xf_consent with their own cache_turbo_key_cookie.
 *
 * `/api/` is the XF REST API (docs.xenforo.com/manual/reference/rest-api). It
 * authenticates on the XF-Api-Key REQUEST HEADER, never a cookie or the standard
 * Authorization header — so an API client's private response carries NONE of the
 * bypass cookies above, and a shared cache keyed on URL alone would store one
 * client's data and serve it to the next. The header is invisible to the cookie
 * rules, so /api/ must bypass on the URI. (This is the same class of bug as the
 * xf_session leak: a real cross-CLIENT leak, closed here on the URI.)
 *
 * `_xfToken` is XF's CSRF token as a QUERY ARG (stock XF hangs it off GET links
 * such as the logout link and the style-variation switcher). Its value is
 * per-session, so any GET carrying it is per-user and must never be cached or
 * served across visitors. The bare `t` alias XF also accepts is NOT matched: it
 * is too generic (tracking params, timestamps) to bypass safely on a preset, and
 * the surfaces that use it (logout, misc/style-variation) are already covered by
 * the /logout and /misc URI rules. An operator with a custom GET route that
 * takes `t` adds it with their own cache_turbo_bypass.
 *
 * All names honour $config['cookie']['prefix'] (default "xf_"); a forum that
 * changed the prefix needs its own cache_turbo_bypass. URIs are the XF2 dynamic
 * surfaces: auth flows, the admin and installer entry scripts, /api/ (REST), and
 * /misc (the style/language picker + inline dispatch endpoints). /contact is NOT
 * a stock XF2 route — the real one is misc/contact, already covered by /misc.
 * /conversations is the pre-2.3 DM route; XF 2.3 renamed it to /direct-messages
 * and permanently redirects the old path, so BOTH are listed (the redirect is a
 * cacheable object we do not want captured under a member's session either).
 */
static const char *const  ct_xf_cookies[] = {
    "xf_session", "xf_user", "xf_session_admin", "xf_lscxf_logged_in", NULL };
static const char *const  ct_xf_uris[] = {
    "/admin.php", "/install/", "/api/", "/login", "/logout", "/lost-password",
    "/register", "/account", "/conversations", "/direct-messages",
    "/misc", NULL };
static const char *const  ct_xf_args[] = { "_xfToken", NULL };
static const char *const  ct_xf_key_cookies[] = {
    "xf_style_id", "xf_style_variation", "xf_language_id", NULL };

/*
 * Discourse. One cookie: `_t`, the auth token (lib/auth/default_current_user_
 * provider.rb — TOKEN_COOKIE, deleted outright for anonymous requests, and the
 * exact test Discourse's own anon cache uses). `_forum_session` is the Rails
 * session cookie and is issued to EVERY visitor including guests, so it is the
 * xf_session trap wearing a different hat: bypassing on it would drop all guest
 * traffic out of the cache. `theme_ids` / `forced_color_mode` are presentation
 * variants (Discourse folds them into its own cache KEY) — they belong in
 * cache_turbo_key, not here. `_t` is renameable via DISCOURSE_TOKEN_COOKIE; a
 * site that renamed it needs its own cache_turbo_bypass.
 *
 * Note Discourse ships its own anonymous page cache and already sends
 * Cache-Control: no-store on authenticated responses, so this preset is mostly
 * defence-in-depth. The api_key/api_username args mark API calls.
 *
 * The rule is "_t=", not "_t": a two-character substring would match inside
 * unrelated names and values (_gat, utm_term=...). Keeping the "=" pins it to a
 * name/value boundary. It can still over-match a cookie literally named
 * "<something>_t" (e.g. "list_t"), which costs a needless bypass but never
 * leaks; a substring matcher cannot do better, and "; _t=" would miss the case
 * where _t is the first cookie in the header.
 *
 * `/u/` (public user profiles) is deliberately ABSENT: profiles are anonymous-
 * identical and Discourse's own anon cache caches them, so bypassing was a pure
 * hit-rate loss. The route is `/drafts` (plural — resources :drafts in
 * config/routes.rb); the singular `/draft` shipped earlier matched only via the
 * old boundary-less prefix test and stops matching `/drafts.json` under the
 * segment-boundary matcher, so it is corrected to the real name here.
 */
static const char *const  ct_discourse_cookies[] = { "_t=", NULL };
static const char *const  ct_discourse_uris[] = {
    "/admin", "/session", "/auth/", "/login", "/logout", "/signup",
    "/my/", "/message-bus/", "/drafts", "/presence/", "/notifications",
    "/user_actions", NULL };
static const char *const  ct_discourse_args[] = {
    "api_key", "api_username", NULL };

/*
 * phpBB 3.x. NO COOKIE RULE — and that is deliberate, not an omission.
 *
 * phpBB's cookie names are <cookie_name>_u / _k / _sid where the prefix is set
 * in the ACP and randomised by many installers, so no substring is shippable
 * (the joomla problem). Worse, session_create() sets all three for every
 * non-bot visitor INCLUDING guests (phpbb/session.php — the set_cookie() block
 * is guarded on $bot, not on login state; an anonymous visitor gets _u=1, the
 * ANONYMOUS user id, plus a real _sid). Telling a logged-in user apart from a
 * guest therefore requires a VALUE test (_u != 1, or _k non-empty), and this
 * registry matches cookie-name substrings only — presence, never value. A _u or
 * _sid rule here would match every anonymous visitor and take the hit rate to
 * zero while still not identifying an authenticated one.
 *
 * So: ship the URI rules (phpBB's dynamic surface is .php entry scripts, which
 * are at least distinctive), ship no cookie rule, and document loudly that the
 * operator MUST add their own cache_turbo_bypass. See docs/phpbb.md.
 */
static const char *const  ct_phpbb_cookies[] = { NULL };
static const char *const  ct_phpbb_uris[] = {
    "/ucp.php", "/mcp.php", "/adm/", "/posting.php", "/memberlist.php",
    "/search.php", "/report.php", NULL };
static const char *const  ct_phpbb_args[] = { "sid", NULL };

/*
 * phpBB VALUE predicate — the cookie rule the comment above says cannot exist as
 * a NAME rule. Verified against phpbb/phpbb source, not inferred:
 *
 *   includes/constants.php            define('ANONYMOUS', 1);
 *   phpbb/session.php  session_create()
 *       guest:  $this->cookie_data['u'] = ($bot) ? $bot : ANONYMOUS;   // => 1
 *       member: $this->cookie_data['u'] = $this->data['user_id'];      // never 1
 *   phpbb/session.php  set_cookie()
 *       $name_data = rawurlencode($config['cookie_name'] . '_' . $name) . '=' ...
 *
 * So EVERY non-bot visitor carries <cookie_name>_u; a guest's holds the literal
 * 1 (ANONYMOUS is a reserved user row, so a real account never has user_id 1),
 * and a member's holds their id. NE against "1" separates them exactly, which a
 * presence rule cannot do — that is why this preset shipped with no cookie rule
 * and told the operator to hand-write a bypass.
 *
 * THE NAME IS MATCHED BY SUFFIX because the prefix is an ACP setting
 * (config 'cookie_name', default "phpbb", so the wire name is "phpbb_u").
 * Installers randomise it and any admin hosting two boards on one domain changes
 * it. A literal-name rule silently stops matching on such a board — and a bypass
 * rule that stops matching caches the member's page and serves it to strangers.
 * Suffix "_u" is prefix-agnostic. It can over-match an unrelated cookie ending
 * in _u (a needless bypass, never a leak): the safe direction.
 *
 * Absent _u => no opinion => cacheable. Correct: a visitor with no phpBB cookie
 * has no session and is a guest.
 *
 * Known, accepted: _u is attacker-supplied, so anyone can send <x>_u=999 and
 * force their own request to bypass. That is a self-inflicted cache miss, not a
 * leak. It is also a cache-flooding lever, but bounded — bypassed requests are
 * never stored, so it costs origin traffic, not cache keyspace.
 */
static const ngx_http_cache_turbo_cookie_pred_t  ct_phpbb_preds[] = {
    { "_u", NGX_HTTP_CACHE_TURBO_CVOP_NE, "1" },
    { NULL, 0, NULL }
};

/*
 * Drupal 9/10/11. Cookie rule: the "SESS" substring, which covers BOTH
 * SESS<hash> and SSESS<hash> (the TLS variant) in one entry.
 *
 * THIS USED TO SHIP NO COOKIE RULE. That was a LEAK, and the reasoning behind it
 * was factually wrong. The old comment claimed "anonymous readers get no session
 * cookie at all", so the Cache-Control floor alone was enough. Drupal does not
 * work that way: it opens a session for an ANONYMOUS user as soon as anything
 * writes to $_SESSION, and core's own NoSessionOpen docblock names the everyday
 * cases — a status message queued by a form submission, and cart contents. Once
 * that happens the visitor holds SESS<hash>, and a logged-IN user holds the same
 * cookie shape. With no cookie rule, an authenticated response could be stored
 * and served to a stranger the moment the Cache-Control floor was not there to
 * catch it (`cache_turbo_cache_control ignore` removes it, and the README
 * recommends that mode for some origins). Correctness cannot rest on that floor.
 *
 * THE KNOWN COST, accepted deliberately: "SESS" is a substring of PHPSESSID and
 * JSESSIONID, so on a box that co-hosts another PHP or Java app under the same
 * server block, this rule also bypasses on THAT app's session cookie. That is a
 * hit-rate loss, never a leak — and a hit-rate loss on a co-hosted app is not a
 * reason to keep leaking on the Drupal one. An operator who cares can narrow it
 * with their own cache_turbo_bypass $cookie_SESS<their-hash>; see docs/drupal.md.
 *
 * The hash is per-install (derived from the hostname — Core/Session/
 * SessionConfiguration.php), so "SESS" is the ONLY shippable literal; matching
 * the full name is impossible.
 *
 * NOT NO_CACHE. It looks like the obvious addition — it is a fixed literal and it
 * appears in every canonical Drupal VCL — but it is CONTRIB, not core (zero hits
 * in the Drupal 11 core tree; it is Pressflow/Varnish heritage carried by modules
 * like cookie_cache_bypass_adv), and it is set FOR LOGGED-OUT visitors by design
 * (that is its whole purpose: force a cache bypass for a guest who must see fresh
 * content). Matching it costs hits and buys no safety.
 *
 * Drupal still defends itself — `private, must-revalidate` on every authenticated
 * response (EventSubscriber/FinishResponseSubscriber.php) — but that is now
 * defence-in-depth behind the cookie rule, which is the correct ordering.
 */
static const char *const  ct_drupal_cookies[] = { "SESS", NULL };
/*
 * /jsonapi and /oauth are the HEADER-AUTHENTICATED surfaces. The cookie tier
 * cannot see them at all: an API client sends `Authorization: Bearer ...` and
 * no SESS cookie, so every cookie rule above is structurally blind to it.
 *
 *   /jsonapi  core's JSON:API module. The prefix is a container parameter,
 *             `jsonapi.base_path: /jsonapi` (core/modules/jsonapi/
 *             jsonapi.services.yml). It exposes every entity type the site has,
 *             filtered by the requesting account's permissions.
 *   /oauth    simple_oauth, which is contrib rather than core but is the
 *             de-facto OAuth2/OIDC provider for Drupal. Its routes are
 *             /oauth/token, /oauth/authorize, /oauth/userinfo, /oauth/debug,
 *             /oauth/jwks (simple_oauth.routing.yml).
 *
 * /oauth/userinfo is the one that makes this a leak rather than a nicety: it is
 * a GET, authenticated purely by the bearer token, and it returns the token
 * holder's profile. Store that response and the next caller is handed someone
 * else's identity. /oauth/debug has the same shape for token metadata. The
 * token endpoint itself is a POST and RFC 6749 §5.1 requires `no-store` on it,
 * so it was never the interesting one.
 *
 * Core REST (?_format=json on an arbitrary entity path) is NOT coverable by a
 * prefix — it rides on ordinary node URLs. The cookie tier catches the
 * session-authenticated case; a bearer-authenticated core-REST client is not
 * catchable here and is called out in docs/drupal.md.
 */
static const char *const  ct_drupal_uris[] = {
    "/user", "/admin", "/node/add", "/system/", "/core/install.php",
    "/jsonapi", "/oauth", NULL };
static const char *const  ct_drupal_args[] = { NULL };

/*
 * MediaWiki. Cookie prefix is $wgCookiePrefix, which DEFAULTS TO THE DATABASE
 * NAME — so, as with joomla, there is no shippable prefix. What is shippable is
 * the SUFFIX: the identity cookies are <prefix>UserID / <prefix>UserName /
 * <prefix>Token / <prefix>_session, and those tails are distinctive enough to
 * match on.
 *
 * MATCH WHAT UPSTREAM MATCHES. MediaWiki's own getVaryCookies() says it plainly:
 *
 *     "Vary on token and session because those are the real authn determiners.
 *      UserID and UserName don't matter without those."
 *
 * So `Token=` and `_session=` are the load-bearing pair, and they are what is
 * shipped. `UserID=` is kept as a cheap belt-and-braces (it is cleared for an
 * anonymous user, so it costs nothing).
 *
 * `UserName=` IS DELIBERATELY NOT MATCHED, and this is not an oversight —
 * unpersistSession() deliberately does NOT clear it on logout, because it
 * pre-fills the login form. So EVERY visitor who has ever logged in keeps
 * sending <prefix>UserName forever, long after they are anonymous again.
 * Bypassing on it is a permanent hit-rate loss for that visitor with zero safety
 * gain — they are, by then, exactly the shared anonymous reader the cache exists
 * for. It used to be in this list; removing it is a pure win.
 *
 * `_session=` is matched even though an anonymous visitor who merely interacts
 * (edit preview, CSRF token) can acquire one. That is the xf_session trade in
 * miniature and it is the right side of it: upstream names it a real authn
 * determiner, and a bypassed guest costs hits while a cached member leaks.
 *
 * MediaWiki's dynamic surface is in the QUERY ARGS, not the path: /wiki/<Title>
 * is the cacheable read path and /index.php?action=... is the dynamic one. Only
 * the MUTATING actions are listed, enumerated from ActionFactory::CORE_ACTIONS.
 * action=view, =history, =raw, =render, =info, =credits, diff= and oldid= are
 * all deliberately absent — they are deterministic, shared, hot, and perfectly
 * cacheable; bypassing them is a measurable hit-rate loss. veaction= is the
 * VisualEditor entry point and is always dynamic. printable= is a presentation
 * variant and belongs in cache_turbo_key.
 *
 * THIS LIST USED TO BE EMPTY while the comment above claimed it was populated.
 * The rows are new; what follows is why the floor that covered for them is not
 * sufficient on its own.
 *
 * MediaWiki's non-view Cache-Control floor is DEFAULT-DENY, and much stronger
 * than "mutating actions are marked private". OutputPage::$mCdnMaxage starts at
 * 0 (Output/OutputPage.php), and core raises it in exactly one place —
 * Actions/ActionEntryPoint.php::performAction():
 *
 *     if ( UseCdn ) {
 *         if ( $request->matchURLForCDN( $htmlCacheUpdater->getUrls( $title ) ) )
 *             $output->setCdnMaxage( CdnMaxAge );
 *         elseif ( $action instanceof ViewAction )
 *             $output->setCdnMaxage( 3600 );
 *     }
 *
 * So a nonzero s-maxage requires a ViewAction or an exact match against the
 * title's PURGEABLE canonical URLs — an ?action= URL is neither. Every other
 * action falls to `$privateReason = 'no-maxage'` in sendCacheControl() and gets
 * `private, must-revalidate, max-age=0`. None of those conditions is
 * identity-dependent, so this holds for ANONYMOUS requesters too — that was the
 * untested half of the claim, and it checks out. With UseCdn off, the same
 * function takes `$privateReason = 'config'` and everything is private anyway.
 *
 * THE ROWS ARE STILL SHIPPED, for the drupal reason (see ct_drupal_cookies):
 * `cache_turbo_cache_control ignore` switches that floor off, and correctness
 * cannot rest on a floor an operator can remove. The cost of carrying them is
 * ~zero — the read path is /wiki/<Title> with no action argument at all, and
 * every hot ?action= value is deliberately NOT listed.
 *
 * Upstream's own recommended Varnish VCL does lean purely on cookies plus
 * Cache-Control with no path rules — and that remains true of the PATH tier
 * here, which is empty. These are argument rules, not path rules.
 *
 * THERE ARE NO URI RULES, and that is the whole point — it is what "no path
 * rules" above actually means. Three used to be here; all three were wrong:
 *
 *   /index.php  On a STOCK wiki $wgArticlePath is /index.php?title=Foo (or
 *               /index.php/Foo) — i.e. /index.php IS the article read path. This
 *               rule bypassed 100% of article reads on any wiki without short-URL
 *               rewrites. It was the single worst rule in the registry.
 *   /load.php   ResourceLoader: versioned, long-TTL JS/CSS bundles — the hottest
 *               cacheable objects on the site.
 *   /api.php    Same class.
 *
 * Wikimedia's production VCL does not merely cache the latter two, it RING-FENCES
 * them, by ticket number, against a rule that would have made them private:
 *   // Only apply to pages. Don't steal cachability of api.php, load.php, etc.
 *   // (T102898, T113007)
 *   if (req.url ~ "^/wiki/" || req.url ~ "^/w/index\.php" || ...)
 * Their frontend has NO path-based pass rule at all — identity is handled purely
 * by folding the session/Token cookies into the hash. The cookies below plus the
 * Cache-Control floor are the entire mechanism, upstream and here. Do not
 * re-add a path rule without a source that says MediaWiki cannot cache it.
 */
static const char *const  ct_mw_cookies[] = {
    "Token=", "_session=", "UserID=", NULL };
static const char *const  ct_mw_uris[] = { NULL };
static const char *const  ct_mw_args[] = {
    "veaction", "returnto",
    /* ActionFactory::CORE_ACTIONS, mutating half only. The read half
     * (view/history/raw/render/info/credits) is deliberately absent. */
    "action=edit", "action=submit", "action=delete", "action=protect",
    "action=unprotect", "action=purge", "action=rollback", "action=revert",
    "action=watch", "action=unwatch", "action=markpatrolled",
    "action=mcrundo", "action=mcrrestore", NULL };

/*
 * Magento 2 (2.4.x). ONE cookie: X-Magento-Vary. Magento is built to sit behind a
 * shared cache and ships its own reference Varnish VCL
 * (app/code/Magento/PageCache/etc/varnish7.vcl) — this preset is that VCL,
 * translated, with one deliberate and important deviation.
 *
 * X-Magento-Vary is the "this visitor is not the shared anonymous case" signal
 * (Framework/App/Http/Context.php::getVaryString): it is a salted hash of the
 * vary context — customer group, auth flag, currency, store view — and it is
 * computed ONLY from values that differ from their defaults. A plain anonymous
 * visitor on the default store has an all-default context, so getVaryString()
 * returns null and the cookie is not set (it is actively deleted if stale). A
 * logged-in customer, a non-default customer group, or a switched
 * currency/store gets the cookie.
 *
 * WE KEY ON THE VALUE, exactly as Magento's VCL does (vcl_hash: hash_data of the
 * regsub'd cookie), via the preset `key_cookies` list. vcl_recv never passes on
 * this cookie; it passes on URL and method only. Magento's OWN built-in PHP full-
 * page cache agrees — Framework/App/PageCache/Identifier.php folds
 * COOKIE_VARY_STRING into the sha1 cache id. Two independent upstream
 * implementations, one call: the vary value is a cache-key component.
 *
 * WHY NOT BYPASS (what this preset used to do). The cookie is a SEGMENT
 * FINGERPRINT, not an identity: sha256 over the SORTED tuple {customer_group,
 * customer_logged_in, store, currency} (App/Http/Context.php::getVaryString), and
 * getData() drops every value equal to its default. So a plain anonymous visitor
 * has NO cookie, and a guest who merely switched currency or store view has one
 * while holding zero private data. Bypassing sent all of them to the origin. The
 * "it prevents a cart leak" premise was false besides: the cart is NOT in the
 * cached HTML — Magento's private-content/sections JS fetches it client-side, and
 * two logged-in shoppers in the same group/store/currency are DESIGNED to receive
 * byte-identical cached HTML.
 *
 * WHY NOT PRESENCE-KEY. Keying on mere presence would collapse a EUR guest, a
 * wholesale customer and a logged-in retail customer into ONE bucket — that IS
 * the cross-user leak. Presence-keying and value-keying are different things;
 * rejecting the first does not justify bypassing.
 *
 * THE TRANSITION RACE (the one genuine leak, invisible from the request side):
 * a request with NO vary cookie hashes to the anonymous bucket, and the RESPONSE
 * sets X-Magento-Vary. Storing that segmented body under the anonymous key
 * poisons it for everyone. Upstream refuses to cache exactly this
 * (vcl_backend_response: beresp.uncacheable when the request had no vary cookie
 * and the response sets one). We inherit the identical refusal from the
 * Set-Cookie floor in ngx_http_cache_turbo_response_policy(): the response
 * that establishes the segment carries a Set-Cookie, so it is never stored,
 * under any key. This preset DEPENDS on that floor, and the floor says so.
 * The floor's only relax (P5-8's cache_turbo_ignore_set_cookie) is hard-vetoed
 * for any location with an active backend preset, so the dedicated preset veto
 * that would have been dead code when this was written now exists.
 *
 * The raw Cookie header is parsed directly because nginx does NOT expose a
 * hyphenated cookie via $cookie_ (there is no '-' -> '_' translation for cookie
 * names, unlike headers), so `$cookie_X_Magento_Vary` silently never matches — a
 * `map` on $http_cookie is the only variable-level workaround, and the module's
 * own parser makes it unnecessary.
 *
 * COOKIES DELIBERATELY NOT LISTED — every one of these is set for ANONYMOUS
 * visitors, and bypassing on any of them takes the hit rate to ~0:
 *   PHPSESSID              sessions are site-wide; everyone gets one
 *   form_key               CSRF token, set client-side for everyone
 *   private_content_version set on ANY POST by anyone (guest add-to-cart,
 *                          newsletter) and then persists for TEN YEARS —
 *                          a slow-motion hit-rate collapse
 *   mage-cache-sessid      set by JS for everyone
 *   section_data_ids       set by JS for everyone
 *   mage-messages          flash queue; anons get these too
 *   mage-cache-storage     not a cookie at all — a localStorage namespace
 *   mage-customer-login    presence != logged-in (it stores a true/false VALUE)
 *
 * Most of the safety here is NOT these rules: cart, checkout, checkout success
 * and the customer-account layouts are all cacheable="false", so Magento emits
 * `no-store, no-cache, must-revalidate` (Framework/App/Response/Http.php
 * ::setNoCacheHeaders) and the implied cache_control honor already refuses to
 * store them. The URI list is defence-in-depth.
 *
 * /admin is deliberately ABSENT: the admin path is randomised per install
 * ("admin_" + 7 random base36 chars — Framework/Setup/BackendFrontnameGenerator),
 * so no shippable prefix matches it. It does not need one: admin always sends
 * no-store. /cart and /onepage are absent because they are not stock routes (the
 * real paths are /checkout/cart and /checkout/onepage) — as position-0 prefixes
 * they would match nothing, while /cart could false-positive on a catalog URL key
 * like /cartridge-refill.
 */
static const char *const  ct_magento_cookies[] = { NULL };
/*
 * /rest and /soap are the Web API front names, and they are the HEADER-
 * AUTHENTICATED surface the cookie tier is structurally blind to. Magento
 * declares all three in app/code/Magento/Webapi/etc/di.xml:
 *
 *     <item name="webapi_rest" ...><item name="frontName">rest</item>
 *     <item name="webapi_soap" ...><item name="frontName">soap</item>
 *
 * `GET /rest/V1/customers/me` with `Authorization: Bearer <customer token>`
 * returns that customer's name, e-mail and address book. No cookie is involved,
 * so no cookie rule can see it; the request carries its identity in a header.
 * /graphql was already listed and is the same class — /rest and /soap were the
 * missing twins, not a new idea.
 *
 * The Authorization storage floor does refuse to store these, but that floor is
 * the same defence-in-depth argument the comment above makes for the rest of
 * this list, and the URI rule is what stops the LOOKUP as well as the store.
 */
static const char *const  ct_magento_uris[] = {
    "/checkout", "/customer", "/graphql", "/rest", "/soap", "/sales",
    "/newsletter", "/wishlist", "/paypal", "/review",
    "/page_cache/block/esi", "/health_check.php", NULL };
static const char *const  ct_magento_args[] = { NULL };
/* Value-keyed, never bypassed. Exact name — see ngx_http_cache_turbo_cookie_value. */
static const char *const  ct_magento_key_cookies[] = { "X-Magento-Vary", NULL };

/*
 * Ghost (5.x/6.x). The public blog is a large, genuinely shared anonymous surface,
 * which is what makes it worth caching at all.
 *
 * DO NOT reason "a member sees the same HTML as a guest on a public post." It is
 * FALSE, and an earlier version of this comment said it. checkPostAccess()
 * (services/members/content-gating.js) does early-return on visibility ===
 * 'public' — but `@member` is injected into the template context UNCONDITIONALLY
 * whenever req.member exists (update-local-template-options.js), so a stock
 * {{#if @member}} in the theme changes the markup of a FULLY PUBLIC post. Ghost
 * itself agrees: frontend-caching.js sets `Cache-Control: private` for ANY member
 * request without ever consulting visibility. The cookie bypass below is what
 * keeps this correct — it is load-bearing, not defence-in-depth.
 *
 * ghost-members-ssr is the members session cookie (services/members/service.js),
 * set ONLY on login — an anonymous reader gets no cookie at all, which is the
 * property Moodle and the PHP shops lack. The substring also covers the
 * ghost-members-ssr.sig signature cookie, so one entry does both.
 *
 * THE ARGS ARE LOAD-BEARING, not decoration — each one authenticates or unlocks
 * WITHOUT A COOKIE, so the cookie rule above cannot catch them:
 *   uuid + key  authMemberByUuid() (services/members/middleware.js) authenticates
 *               a member purely from the QUERY STRING, HMAC-verifying key against
 *               uuid. No cookie is involved at any point.
 *   token       the magic-link signin.
 *   gift        a ?gift render serves UNLOCKED GATED CONTENT with no member
 *               cookie present. Ghost's own cache middleware refuses to store it
 *               for exactly this reason (isGiftRequest()).
 * Store any of these and the paid/gated body is replayed to strangers. Do not
 * drop them, and do not assume the Cache-Control floor covers you: an operator
 * running `cache_turbo_cache_control ignore` (which the README recommends for
 * some origins) has switched that floor off.
 *
 * /p/ is unpublished post previews (must never be cached) and /r/ is the
 * link-redirect tracker.
 */
static const char *const  ct_ghost_cookies[] = {
    "ghost-members-ssr", "ghost-admin-api-session", NULL };
static const char *const  ct_ghost_uris[] = {
    "/ghost/", "/members/", "/p/", "/r/", NULL };
static const char *const  ct_ghost_args[] = {
    "uuid", "key", "token", "gift", NULL };

/*
 * Wagtail (Django CMS). The first preset for an app whose auth cookie belongs to
 * its FRAMEWORK, not to itself — Wagtail ships no cookie of its own, it rides
 * Django's `sessionid`. That is only shippable because of a specific Django
 * property: SessionMiddleware saves the session cookie ONLY when the session is
 * non-empty AND modified, so a logged-out reader of a public page is issued no
 * cookie at all. Contrast Laravel, whose StartSession has no such check and
 * cookies every guest — which is why there is no statamic/october preset, and no
 * `laravel` preset, and never will be. See docs/frameworks.md.
 *
 * THE CONDITION IS REAL AND IT IS THE APP'S TO BREAK. `sessionid` stops being a
 * logged-in signal the moment the site writes to the session for anonymous
 * visitors: an anonymous cart (request.session['cart']=…), a large guest flash
 * message (contrib.messages overflows cookie storage and falls back to the
 * SESSION), or CSRF_USE_SESSIONS=True. Each turns the bypass into a 100% bypass —
 * hit rate 0, no error, nothing in the log. This FAILS SAFE (lost hits, never a
 * leak), which is the only reason it is shippable at all; docs/wagtail.md tells
 * the operator to re-check with curl after any deploy that touches sessions.
 *
 * NOT csrftoken. Django hands it to every anonymous visitor that renders a form
 * (a search box in the header is enough), so bypassing it would bypass everything
 * and find no logged-in user. Same class as WooCommerce's guest cookies.
 *
 * URIs come from Wagtail's own project template (project_template/project_name/
 * urls.py), so all three are what a stock install actually serves:
 *   /admin/         wagtailadmin_urls — relocatable (the docs suggest /cms/ when
 *                   it clashes with Django admin). An install that moves it loses
 *                   the URI shortcut but stays CORRECT, because `sessionid` is the
 *                   real guard. Cookie guards, URI optimises — that ordering is
 *                   deliberate.
 *   /django-admin/  admin.site.urls — also in the stock template.
 *   /documents/     LOAD-BEARING, not decoration. WAGTAILDOCS_SERVE_METHOD
 *                   defaults to serve_view under FileSystemStorage: a Django view
 *                   that enforces per-collection PRIVACY checks. A private
 *                   document fetched by an authorised user must never be stored
 *                   and replayed to a stranger. Bypass on the prefix rather than
 *                   trusting a no-store header we have not verified.
 *
 * /search/ is deliberately ABSENT. It is dynamic but ANONYMOUS-IDENTICAL — every
 * logged-out visitor searching "foo" gets the same page — so it is shared, hot,
 * and exactly what a cache is for. Bypassing it would be a pure hit-rate loss with
 * no safety gain. Same reasoning that keeps a blanket `action=` out of mediawiki.
 */
static const char *const  ct_wagtail_cookies[] = { "sessionid", NULL };
static const char *const  ct_wagtail_uris[] = {
    "/admin/", "/django-admin/", "/documents/", NULL };
static const char *const  ct_wagtail_args[] = { NULL };

/*
 * Kirby (flat-file PHP CMS). The best-shaped traffic of any preset here: a
 * flat-file site is almost entirely public pages that are byte-identical for every
 * logged-out visitor, which is the whole business case for a page cache.
 *
 * kirby_session is a STABLE literal (session.cookieName default) — no hash, no
 * APP_NAME, no admin-settable prefix — and Kirby creates a session only when
 * something is actually stored in it, so a plain anonymous GET of a public page is
 * issued NO cookie. Stable + not-guest-issued is the pair every rejected candidate
 * failed: Grav's grav-site-<hash> is both guest-issued AND per-install, Craft's
 * CraftSessionId is stable but handed to every visitor, Statamic's is APP_NAME-
 * derived AND guest-issued.
 *
 * THE ONE CONDITION, and it fails SAFE: Kirby's csrf() helper creates a session
 * cookie ("When you use the csrf() helper, Kirby will create a session cookie" —
 * the privacy guide). So a template with a contact/search/comment form issues
 * kirby_session TO GUESTS on that page, and those pages stop caching. That costs
 * HITS on form pages; it never leaks, because the direction of the error is
 * bypass-a-guest, not serve-a-member's-page. Precisely inverted from Flarum, which
 * is why Flarum is rejected and this ships. docs/kirby.md says which pages to
 * expect it on.
 *
 * /panel is the admin (panel.slug, rarely moved). /media is NOT listed: Kirby
 * serves assets from /media/<hash>/ with no per-request permission view, so it is
 * static content that SHOULD cache — bypassing it would be a self-inflicted wound.
 */
static const char *const  ct_kirby_cookies[] = { "kirby_session", NULL };
static const char *const  ct_kirby_uris[] = { "/panel", NULL };
static const char *const  ct_kirby_args[] = { NULL };

/*
 * Shopware 6. VALUE-KEYED, NOT BYPASSED — the same shape as magento, and for the
 * same reason. Read that comment first; this one only records what differs.
 *
 * sw-cache-hash is a purpose-built cache-variant cookie, not an identity.
 * CacheHeadersService::buildCacheHash() folds a SET of fields into it —
 * {rule_ids, version_id, currency_id, tax_state, logged_in_state} — where
 * logged_in_state is literally 'logged-in' | 'not-logged-in' (CacheHeadersService
 * .php:104). The logged-in bit is INSIDE the value, alongside currency and price
 * rules. Shopware's own reverse proxy treats it exactly as a key and never as a
 * bypass (shopware/varnish-shopware default.vcl: hash_data("+context=" +
 * cookie.get("sw-cache-hash"))), which is the behaviour we are matching.
 *
 * WHY A BYPASS WOULD BE WRONG, precisely: isCacheHashRequired() (:125) returns
 * true for a logged-in customer OR a guest with a filled cart OR a guest on a
 * non-default currency. So bypass-on-presence would send cart-holding GUESTS and
 * non-default-currency GUESTS to the origin — anonymous visitors whose private
 * data is not in the cached HTML at all (the cart is fetched client-side, as in
 * magento). That is the exact bypass #28 removed from magento; do not reintroduce
 * it here. Presence is not identity; the value is a segment fingerprint.
 *
 * LAZY, and actively so — this is the (b) half of the screening question, and
 * Shopware enforces it harder than any other preset here. When the hash is NOT
 * required, applyCacheHash() (:62) does not merely omit the cookie, it DELETES a
 * stale one (removeCookie + clearCookie). A default anonymous visitor is
 * guaranteed cookieless, so the anonymous bucket is the common case.
 *
 * sw-states IS DELIBERATELY NOT MATCHED, and matching it would be a LEAK on a
 * current shop. It was REMOVED in 6.8 (UPGRADE-6.8.md: "Removed `sw-states` and
 * `sw-currency` cache cookie handling ... The complete caching behaviour is now
 * controlled by the `sw-cache-hash` cookie"); HttpCacheKeyGenerator::
 * SYSTEM_STATE_COOKIE is @deprecated tag:v6.8.0 and CacheResponseSubscriber gates
 * the whole path off under Feature::isActive('v6.8.0.0'), so 6.8 never sets it. A
 * preset keyed on sw-states alone would silently stop firing on an upgraded shop
 * — the classic "matcher stops matching => logged-in pages get cached" failure.
 * sw-cache-hash spans 6.4..6.8, so one exact literal covers every supported line.
 *
 * The name is a stable literal (HttpCacheKeyGenerator::CONTEXT_CACHE_COOKIE =
 * 'sw-cache-hash', :27) — no per-install hash, no APP_NAME, not admin-settable.
 * It is hyphenated, so $cookie_sw_cache_hash would never match; the module's raw
 * Cookie parser is what makes it usable (see the magento note).
 *
 * /account and /checkout are stock Storefront routes and stay bypassed as
 * defence-in-depth (Shopware sends no-store on them anyway). /admin is the API +
 * Administration SPA. /store-api is the headless JSON API: it is context-sensitive
 * per sw-context-token and must never be shared.
 */
static const char *const  ct_shopware6_cookies[] = { NULL };
static const char *const  ct_shopware6_uris[] = {
    "/account", "/checkout", "/admin", "/api", "/store-api", NULL };
static const char *const  ct_shopware6_args[] = { NULL };
/* Value-keyed, never bypassed. Exact name — see ngx_http_cache_turbo_cookie_value. */
static const char *const  ct_shopware6_key_cookies[] = { "sw-cache-hash", NULL };

/*
 * TYPO3 (v11..v13). Lazy sessions, confirmed at the strongest possible place: the
 * frontend authentication object opts OUT of cookies by default.
 * FrontendUserAuthentication::$dontSetCookie = true (:155) OVERRIDES the base
 * class default of false (AbstractUserAuthentication:199), and it is flipped back
 * to false in exactly two places, both on the login path — createUserSession()
 * (:242) and regenerateSessionId() (:407). shallSetSessionCookie() (:344) is the
 * gate. So an anonymous visitor reading public pages is issued NO cookie: this is
 * a deliberate upstream design decision in favour of caching, not an accident we
 * are relying on.
 *
 * THE ONE CAVEAT, and it is a real one: the name is admin-overridable, NOT a hard
 * literal. FrontendUserAuthentication::getCookieName() (:167) reads
 * $GLOBALS['TYPO3_CONF_VARS']['FE']['cookieName'] and falls back to 'fe_typo_user'.
 * It is a plain default rather than a per-install hash (unlike Drupal's SESS<hash>
 * or Grav's grav-site-<hash>), and overriding it is rare — but a site that DOES
 * override it silently loses the match, and a lost match on a bypass rule means
 * logged-in pages get cached. docs/typo3.md says: if you set FE/cookieName, add
 * your name with cache_turbo_bypass_cookie. We match the default exactly; we
 * cannot match a name we cannot know.
 *
 * be_typo_user is matched too, and is a genuine stable literal. It is not
 * redundant with the FE cookie: an editor previewing the frontend, or any backend
 * user hitting a FE page, carries only the BE cookie, and TYPO3 renders
 * hidden/scheduled records and preview versions for them. Caching that response
 * would publish unpublished content to strangers. Same class as xenforo's
 * xf_session_admin — a second cookie, a second table, an independent lifetime.
 *
 * /typo3 is the backend entry point (stable; TYPO3 does not randomise it the way
 * magento randomises /admin).
 */
static const char *const  ct_typo3_cookies[] = {
    "fe_typo_user", "be_typo_user", NULL };
static const char *const  ct_typo3_uris[] = { "/typo3", NULL };
static const char *const  ct_typo3_args[] = { NULL };

/*
 * Invision Community (IPS4). Closed-source, vendor-attested rather than
 * source-verified — IPS's own developer docs document ips4_loggedIn as
 * existing FOR THIS EXACT PURPOSE: "set after login, used by caching systems
 * to identify if you are logged in" (Common Cookies Set By The Suite / the
 * Caching developer guide, which tells a page-cache integrator to check it
 * before initialising other classes). This is a stronger, purpose-built signal
 * than most platforms in this registry ship — most forums leave you to reverse
 * engineer a remember-me cookie; IPS names the caching cookie for you.
 *
 * `ips4_IPSSessionFront` is issued to EVERY visitor, guests included (ordinary
 * session tracking) — the same xf_session/_forum_session shape, and it is
 * deliberately NOT in this list.
 *
 * The `ips4_` prefix is admin-configurable (Overriding Default Cookie Options),
 * so the rule matches the SUFFIX `_loggedIn`, not the literal `ips4_loggedIn`
 * — the same prefix-agnostic technique phpBB's `_u` and Drupal's `SESS` use.
 *
 * IPS routes through app=core&module=...&do=... controller dispatch rather
 * than one stable posting URI, so posting/messaging/moderation surfaces are
 * matched as `do=` query args, not URI prefixes, alongside the fixed
 * front-controller paths (/login, /register, /lostpassword, /messenger, and
 * /admin — the ACP).
 *
 * key_cookies are cosmetic (theme, language, JS detection), shared by everyone
 * who picked the same value — never an identity signal.
 *
 * `ips4_device_key` is deliberately NOT keyed, and it is the counter-example
 * that defines the rule: it is a PER-DEVICE fingerprint, so it is neither
 * cosmetic nor shared. Keying on it gives every visitor a private entry nobody
 * else can ever hit, and because the value comes straight from the client it
 * also lets one attacker mint unlimited distinct keys and push the zone into
 * eviction. Same reasoning as ct_vbulletin_key_cookies. It carries no variant
 * information either: IPS sets it on the login POST for the remember-me device
 * list, so its bearer is a MEMBER, and those requests the _loggedIn predicate
 * has already bypassed. (It is httpOnly, but that is irrelevant here — httpOnly
 * only hides a cookie from browser script; it is still sent in the Cookie
 * header and this module sees it like any other.)
 */
static const ngx_http_cache_turbo_cookie_pred_t  ct_invision_preds[] = {
    { "_loggedIn", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { NULL, 0, NULL }
};
static const char *const  ct_invision_cookies[] = { NULL };
static const char *const  ct_invision_uris[] = {
    "/admin", "/login", "/register", "/lostpassword", "/messenger", NULL };
static const char *const  ct_invision_args[] = {
    "do=compose", "do=post", "do=reply", "do=report", "module=messaging", NULL };
static const char *const  ct_invision_key_cookies[] = {
    "ips4_hasJS", "ips4_theme", "ips4_language", NULL };

/*
 * Simple Machines Forum (SMF). SMFCookie (name is `$cookiename` from
 * Settings.php, default "SMFCookie" + version suffix e.g. SMFCookie20/21, so
 * the rule matches the SUBSTRING "SMFCookie" not a full literal) is issued to
 * EVERY visitor, guests included — the phpBB shape exactly. loadUserSettings()
 * in SMF's own core only treats it as authenticated when the embedded
 * password-hash element is non-empty; a guest's value carries id_member=0 and
 * an empty password field.
 *
 * A general-purpose nginx cookie matcher cannot safely JSON/PHP-serialize
 * decode the structured value and validate hash shape, so the pragmatic proxy
 * (same class of compromise as phpBB's presence-of-suffix rule) is: bypass
 * whenever the cookie is present AT ALL. This is presence-only despite the
 * cookie being guest-issued, and it is NOT free — it costs hit rate on guests
 * who have merely started a session (viewed the login page, tripped 2FA).
 * That is the accepted XenForo-style trade: correct, not maximally fast. Do
 * not "optimise" this into a value predicate without actually parsing the
 * cookie's array/JSON structure — an approximate string-prefix guess against
 * a guest-canonical value is not a safe substitute for a real decode, and
 * shipping one un-decoded risks the opposite failure (misclassifying an
 * authenticated cookie as guest-shaped).
 *
 * The 2FA companion cookie `<cookiename>_tfa` only exists mid-login and is
 * folded into the same presence rule for completeness.
 */
static const char *const  ct_smf_cookies[] = { "SMFCookie", NULL };
static const char *const  ct_smf_uris[] = { NULL };
static const char *const  ct_smf_args[] = {
    "action=admin", "action=login", "action=login2", "action=logintfa",
    "action=logout", "action=profile", "action=pm", "action=post",
    "action=post2", "action=moderate", "action=reporttm", "action=xmlhttp",
    NULL };

/*
 * Vanilla Forums. The `Vanilla` identity cookie (Gdn_CookieIdentity::
 * SetIdentity()) is written ONLY at login/SSO time — a true guest never
 * receives it at all, unlike the phpBB/SMF/XenForo shape. No value predicate
 * is needed or available (the value is an HMAC-signed opaque payload).
 *
 * CAVEAT: this is corroborated via Vanilla's own KB article and community
 * threads describing SetIdentity/GetIdentity, not a direct line-cited GitHub
 * source read (the exact file could not be fetched at research time — it may
 * have moved in the TypeScript/PHP8 rewrite of newer Vanilla). Ship it, but
 * verify empirically against your own install (curl anonymously, confirm no
 * `Set-Cookie: Vanilla=...` appears) before relying on it in production.
 *
 * The rule matches "Vanilla=" — the identity cookie's name followed by its
 * delimiter — NOT the bare substring "Vanilla". Vanilla derives several
 * GUEST-issued cookie names from the same `Garden.Cookie.Name` prefix
 * (`Vanilla-tk`, the CSRF transient key, and `Vanilla-Vv`, the visit
 * tracker), so a bare-prefix match would fire on ordinary anonymous traffic
 * and collapse the hit rate to cookieless first hits and crawlers — the
 * guest-issued-cookie trap this registry's header comment forbids. The
 * trailing '=' is what separates the identity cookie from its siblings.
 *
 * Renaming `Garden.Cookie.Name` therefore defeats this rule; docs/vanilla.md
 * tells the operator to add their own cache_turbo_bypass in that case.
 */
/*
 * NO /api ROW, DELIBERATELY, and this is an unresolved gap rather than a
 * decision. Vanilla's API v2 is Bearer-authenticated, so it is exactly the
 * header-auth surface the cookie tier cannot see — the same class as magento
 * /rest, drupal /jsonapi and xenforo /api/, all of which ARE listed.
 *
 * It is not listed here because it cannot be verified: github.com/vanilla/vanilla
 * now 404s (repo, raw and API alike; the org survives), so there is no upstream
 * tree left to check the prefix against, and every surviving reference is a
 * Garden-era fork last pushed in 2013. Adding a row from recollection is exactly
 * what produced the dead /admin.php and /message_send.php rows in punbb, so it
 * is not being done. An operator running Vanilla's API adds their own:
 *     cache_turbo_bypass_uri /api;
 * See docs/vanilla.md.
 */
static const char *const  ct_vanilla_cookies[] = { "Vanilla=", NULL };
static const char *const  ct_vanilla_uris[] = {
    "/dashboard", "/entry/", "/messages/", "/post/", NULL };
static const char *const  ct_vanilla_args[] = { NULL };

/*
 * PunBB. The session cookie is issued EAGERLY to every guest too
 * (set_default_user(), unless
 * FORUM_QUIET_VISIT), so this needs the phpBB-shaped value predicate, not
 * presence. Unlike phpBB's derived `_u` flag, PunBB's cookie value is a
 * base64'd, pipe-delimited string whose FIRST field IS the numeric user_id
 * directly — a guest's is the hardcoded literal "1" (login.php: logout path
 * writes `base64_encode('1|'.random_key(...))`; a real login writes the
 * actual user_id, which by the same ANONYMOUS-reserved-row convention as
 * phpBB is never 1). The registry's cookie_preds engine tests the request
 * Cookie header directly (not decoded base64), so the predicate here matches
 * against the cookie's RAW value with the NE-vs-guest-literal test applied to
 * the same base64'd guest string PunBB itself always writes for a logged-out
 * visitor — see the predicate below.
 *
 * Fixed literal URI prefixes for admin/login/posting/editing/moderation bypass
 * unconditionally. There is no private-messaging row: PunBB core ships no PM
 * (an earlier version of this comment claimed it did) -- see the URI list.
 *
 * IMPLEMENTATION NOTE: the ideal rule (base64-decode, split on '|', compare
 * field[0] against the guest literal "1") is NOT expressible by this engine's
 * cookie_preds — it compares the RAW cookie value against a fixed literal
 * (EQ/NE) or tests non-emptiness, and PunBB's base64'd guest value carries a
 * random per-request key suffix after the "1|" (`base64_encode('1|'.
 * random_key(...))`), so it is never one fixed string an EQ/NE test can
 * anchor on. A prefix-of-decoded-value predicate would require actually
 * decoding base64 in the hot classify path, which this registry does not do
 * anywhere else (all other value predicates compare the wire bytes directly).
 * So this preset degrades to PRESENCE-only, same shape as SMF's SMFCookie —
 * safe (bypass is the correct-direction failure), but costs hit rate on
 * guests who merely touched a session-starting action. docs/punbb.md notes
 * this rather than claiming the sharper rule the research suggested.
 *
 * COOKIE NAME: PunBB 1.4.x defaults to `forum_cookie`, and its installer
 * offers a randomised `forum_cookie_<rand>`; `punbb_cookie` was the 1.2-era
 * default and still appears on upgraded boards. Both are matched as
 * substrings, so the randomised 1.4 variant is covered by the `forum_cookie`
 * entry. Matching only `punbb_cookie` (as this row originally did) never
 * fired on a stock 1.4 install, which served cached guest pages to logged-in
 * members. An operator who renames `$cookie_name` to anything else must add
 * their own cache_turbo_bypass — docs/punbb.md says so.
 */
static const char *const  ct_punbb_cookies[] = {
    "forum_cookie", "punbb_cookie", NULL };
/*
 * URI list, verified against the punbb/punbb tree at tag v1.4.4. Every entry
 * below is a script that exists at the document root of a stock install.
 *
 * Three rows were removed because NO PunBB release ships them:
 *   - "/admin.php": 1.4.x keeps the admin under the "/admin/" DIRECTORY
 *     (admin/index.php, admin/users.php, admin/settings.php, ...), and the
 *     1.2-era layout used admin_index.php / admin_users.php at the docroot.
 *     Neither is "/admin.php". The 1.2 layout is also NOT expressible here:
 *     uri_prefix() requires the byte after the needle to be '/' or '.', so a
 *     partial-filename needle like "/admin_" can never match "/admin_index.php"
 *     -- listing every 1.2 admin script individually would be the only way, and
 *     1.2 has been EOL since 2013. Losing it costs nothing anyway: an admin is
 *     by definition logged in, so the cookie tier bypasses them already, and
 *     the admin scripts re-check g_id server-side.
 *   - "/message_send.php", "/message_delete.php": private messaging is NOT a
 *     PunBB core feature (the comment above previously claimed it was). Core
 *     has no PM at all -- misc.php carries the email-a-user and report-a-post
 *     forms instead -- and the third-party PM extensions route through their
 *     own extension paths, not these two names.
 *
 * Five real member/mutating scripts were missing and are now listed: edit.php,
 * delete.php, moderate.php, profile.php, register.php. search.php and
 * userlist.php are deliberately absent -- both are guest-reachable read
 * surfaces that cache correctly.
 */
static const char *const  ct_punbb_uris[] = {
    "/admin/", "/login.php", "/post.php", "/edit.php", "/delete.php",
    "/moderate.php", "/profile.php", "/register.php", "/misc.php", NULL };
static const char *const  ct_punbb_args[] = { NULL };

/*
 * Phorum. Fixed, version-pinned literal session-cookie constants
 * (phorum_session_v5, phorum_session_st, phorum_admin_session — PHP
 * constants in include/api/user.php, not per-install hashes or
 * admin-configurable prefixes) written ONLY by
 * phorum_api_user_session_create(), which is called ONLY from a successful
 * login — never for anonymous page rendering. This is the inverse of the
 * XenForo/Discourse/phpBB/Flarum trap: presence alone is a safe, sufficient
 * signal because guests never receive any of these three cookies. No value
 * predicate needed.
 *
 * `phorum_tmp_cookie` is a guest-received cookie-support PROBE with no
 * identity value (destroyed once logged in) — deliberately absent from the
 * list; matching it would be a pure hit-rate loss for zero safety gain.
 *
 * Phorum is a flat top-level-script app (admin.php, login.php, ... — no path
 * hierarchy), so the dynamic surface is expressed as URI prefixes against
 * those script names directly.
 */
static const char *const  ct_phorum_cookies[] = {
    "phorum_session_v5", "phorum_session_st", "phorum_admin_session", NULL };
/*
 * Verified against Phorum/Core master. "/file.php" is the row that matters
 * most and was missing: it is the ATTACHMENT DOWNLOAD script, and it authorises
 * per request through the file_storage API (a file attached to a private-forum
 * message is refused to anyone without read access to that forum). Serving it
 * from the cache hands the first requester's attachment body to every later
 * requester of the same file id, permission check skipped -- the same shape as
 * the phpBB download/file.php hazard.
 *
 * "/post.php" is kept even though Phorum 5 replaced it with posting.php: the
 * file still ships, as a stub whose entire body is a die() that exists to
 * overwrite the 5.0 script on upgrade so spammers cannot POST to it. Bypassing
 * a die() page costs nothing and the row is one byte of table.
 */
static const char *const  ct_phorum_uris[] = {
    "/admin.php", "/login.php", "/register.php", "/pm.php", "/posting.php",
    "/post.php", "/moderation.php", "/control.php", "/ajax.php", "/report.php",
    "/follow.php", "/file.php", NULL };
static const char *const  ct_phorum_args[] = { NULL };
static const char *const  ct_phorum_key_cookies[] = { "list_style", NULL };

/*
 * YaBB (the Perl forum). The three session/login cookies (`Y2User-<rand>`,
 * `Y2Pass-<rand>`, `Y2Sess-<rand>`) get a RANDOM per-install numeric suffix
 * generated once by Setup.pl — the Joomla-shaped naming problem — but the
 * FIXED PREFIXES (`Y2User-`, `Y2Pass-`, `Y2Sess-`) survive it, so the rule
 * matches those substrings, not a full name.
 *
 * More importantly: presence alone is safe regardless of the prefix, because
 * the single write path (UpdateCookie("write", ...)) is called ONLY from the
 * post-login-form-POST success branch in LogInOut.pl. Every guest / logged-out
 * / failed-login path calls UpdateCookie("delete") instead, which clears these
 * three cookies (or, in guest-language-cookie mode, repurposes only the
 * Y2Pass- slot to hold a plaintext "guestlanguage" string — cosmetic, not an
 * auth artifact). YaBB also always cookies on login regardless of a
 * remember-me checkbox (UpdateCookie("write") on LogInOut.pl:101 fires for
 * ANY successful login; only the expiry varies) — so this has none of the
 * XenForo/Flarum "ordinary login leaves no cookie" trap either.
 *
 * A site that hand-renames the three Y2*-prefixed cookie vars away from the
 * convention breaks this preset silently — same caveat class as any other
 * admin-configurable cookie name in this registry (document, don't code
 * around what can't be discovered).
 *
 * YaBB is a single-script CGI app (YaBB.pl?action=X), so the dynamic surface
 * lives in query args, not URI prefixes.
 *
 * `action=logout` is in the args list for the same reason `action=login` is,
 * and it is the more dangerous of the pair to omit: a cached logout response
 * is served without the request ever reaching LogInOut.pl, so the
 * UpdateCookie("delete") that terminates the session never runs and the member
 * stays logged in while being told they are not.
 */
static const char *const  ct_yabb_cookies[] = {
    "Y2User-", "Y2Pass-", "Y2Sess-", NULL };
static const char *const  ct_yabb_uris[] = { NULL };
static const char *const  ct_yabb_args[] = {
    "action=post", "action=post2", "action=login", "action=login2",
    "action=logout", "action=register", "action=register2", "action=admin",
    "action=pm", "action=imsend", "action=imsend2", NULL };

/*
 * MyBB. The login cookie is `mybbuser` — the whole of that is MyBB's own
 * hardcoded base name (my_setcookie("mybbuser", ...)); the ACP `cookieprefix`
 * setting is PREPENDED to it and defaults to EMPTY. An earlier version of this
 * comment had it backwards ("COOKIE_PREFIX default mybb_"), which matters
 * because it makes the prefix look like a fixed, known string when it is
 * operator-chosen and undiscoverable from the request.
 *
 * It is written ONLY inside the login success path (inc/datahandlers/login.php
 * via member.php do_login) — a guest structurally cannot receive it, so
 * presence alone is sufficient with no value predicate. Because the prefix is
 * operator-set, the rule matches the SUFFIX "user", the same prefix-agnostic
 * technique phpBB's "_u" uses; a predicate can afford that because its failure
 * direction is a needless bypass (`coppauser`, a real MyBB cookie, also ends in
 * "user" and costs a registrant's hit rate — nothing worse).
 *
 * `sid` (session id) is issued to EVERY visitor including guests and bots —
 * deliberately NOT in this list; it is the same xf_session/SMFCookie trap. The
 * various `mybb[lastvisit]`, `[threadread]`, `[forumread]`, `[readallforums]`,
 * `[announcements]` array-cookies are guest read-tracking, not auth — also
 * excluded. `mybbtheme` / `mybblang` are presentation cookies, folded into the
 * key instead of bypassed.
 *
 * THE KEY COOKIES DO NOT GET THE SUFFIX TREATMENT, deliberately. On a board
 * that sets a `cookieprefix` the wire names become `<prefix>mybbtheme` /
 * `<prefix>mybblang`, the exact match below folds nothing, and every guest
 * shares one bucket — whichever theme rendered first is served to all of them.
 * That is a hit-QUALITY bug, and it is the better of the two failures: keying
 * on a suffix would let any client fold a cookie of its own choosing
 * (`evilmybbtheme=dark`) into the key, landing on the same bucket a real
 * `mybbtheme=dark` reader uses while the origin — which ignores the unknown
 * name — returns the DEFAULT theme to be stored there. See the threat model on
 * ngx_http_cache_turbo_cookie_value(): a predicate's loose match costs a
 * bypass, a key's loose match hands out bucket selection.
 *
 * The remedy is operator-side and already exists: a prefixed board declares
 * `cache_turbo_key_cookie <prefix>mybbtheme <prefix>mybblang;`, which folds
 * with the identical framing. docs/mybb.md carries this.
 */
static const ngx_http_cache_turbo_cookie_pred_t  ct_mybb_preds[] = {
    { "user", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { NULL, 0, NULL }
};
static const char *const  ct_mybb_cookies[] = { NULL };
static const char *const  ct_mybb_uris[] = {
    "/member.php", "/usercp.php", "/private.php", "/modcp.php",
    "/newthread.php", "/newreply.php", "/editpost.php", "/polls.php",
    "/admin/", "/xmlhttp.php", NULL };
static const char *const  ct_mybb_args[] = {
    "action=login", "action=do_login", "action=logout", "action=do_logout",
    "action=register", "action=do_register", "action=activate",
    "action=lostpw", "action=do_lostpw", "action=resetpassword", NULL };
static const char *const  ct_mybb_key_cookies[] = {
    "mybbtheme", "mybblang", NULL };

/*
 * vBulletin (3.x/4.x "bb_" cookie-prefix era). `bb_userid` / `bb_password`
 * (or `bbimloggedin=yes` on some builds, confirmed as the real signal ops use
 * in production LiteSpeed vBulletin caching configs) are set ONLY on login
 * and removed on logout — never issued to guests. Presence/non-empty-value
 * alone is sufficient; no value-split trick needed.
 *
 * `bb_sessionhash` is issued to guests too (session tracking for everyone) —
 * deliberately excluded, the xf_session shape again. The `bb_` prefix is
 * admin-configurable (Cookie and HTTP Header Options), so this matches the
 * SUFFIX "userid" / "password", not a hardcoded "bb_" literal — a rare manual
 * full-rename still evades it (documented gap, same class as any other
 * admin-configurable-name caveat in this registry).
 *
 * The style-and-language-selection cookie is presentation, folded into the key
 * rather than bypassed. `bb_lastvisit` / `bb_lastactivity` are presentation too
 * but are NOT key cookies -- see ct_vbulletin_key_cookies below for why keying
 * on a per-request timestamp is both useless and hostile.
 */
static const ngx_http_cache_turbo_cookie_pred_t  ct_vbulletin_preds[] = {
    { "userid", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { "password", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { "imloggedin", NGX_HTTP_CACHE_TURBO_CVOP_EQ, "yes" },
    { NULL, 0, NULL }
};
static const char *const  ct_vbulletin_cookies[] = { NULL };
static const char *const  ct_vbulletin_uris[] = {
    "/login.php", "/register.php", "/usercp.php", "/private.php",
    "/profile.php", "/cron.php", "/admincp/", NULL };
static const char *const  ct_vbulletin_args[] = { NULL };
/* Only bb_language. bb_lastvisit and bb_lastactivity are per-visit timestamps
 * that change on essentially every request, so keying on them gave each visitor
 * a private bucket the next request already invalidated -- a hit rate near zero
 * on a board that otherwise caches well. They were also a free remote memory
 * attack: the values come straight from the client, so anyone could mint
 * unlimited distinct keys and push the zone into eviction. */
static const char *const  ct_vbulletin_key_cookies[] = {
    "bb_language", NULL };

/*
 * Textpattern. Both login cookies are written after every successful login;
 * `txp_login_public` is the frontend signal and `txp_login` protects the admin
 * side. Anonymous public requests do not receive either one. The admin folder
 * defaults to /textpattern but can be renamed, so the guide requires an
 * operator rule when it is moved.
 */
static const char *const  ct_textpattern_cookies[] = {
    "txp_login_public=", "txp_login=", NULL };
static const char *const  ct_textpattern_uris[] = { "/textpattern", NULL };
static const char *const  ct_textpattern_args[] = { NULL };

/*
 * Bludit. Only the admin bootstrap starts the BLUDIT-KEY session; the public
 * bootstrap is session-free. The __Secure- spelling still contains BLUDIT-KEY,
 * and the two remember-me names are stable literals. /install.php is dynamic
 * setup state and must never be replayed from the page cache.
 */
static const char *const  ct_bludit_cookies[] = {
    "BLUDIT-KEY", "BLUDITREMEMBERUSERNAME=", "BLUDITREMEMBERTOKEN=", NULL };
static const char *const  ct_bludit_uris[] = {
    "/admin", "/install.php", NULL };
static const char *const  ct_bludit_args[] = { NULL };

/*
 * SPIP prefixes all of its spip_* cookies with an operator-selected cookie
 * prefix. Suffix predicates preserve the meaningful half of each name and fail
 * toward a bypass if another cookie happens to collide. Language and Ajax-mode
 * cookies are presentation state; bypassing them avoids serving the wrong
 * variant without allowing arbitrary client values into the cache key.
 * `?action=` dispatches action handlers and `?var_mode=` forces preview/debug/
 * recalculation modes, neither of which is a shared page render.
 */
static const ngx_http_cache_turbo_cookie_pred_t  ct_spip_preds[] = {
    { "_session", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { "_admin", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { "_lang", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { "_lang_ecrire", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { "_accepte_ajax", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { NULL, 0, NULL }
};
static const char *const  ct_spip_cookies[] = { NULL };
static const char *const  ct_spip_uris[] = { "/ecrire", NULL };
static const char *const  ct_spip_args[] = { "action", "var_mode", NULL };

/*
 * Bugzilla. Bugzilla_login and Bugzilla_logincookie are both issued on every
 * successful cookie login (remember-me changes only expiry), so they are clean
 * member-only signals. API keys and tokens can authenticate entirely through
 * the query string. The URI list keeps login/account/mutation/admin/API entry
 * points out before a cookie exists while leaving show_bug.cgi, buglist.cgi
 * and reports cacheable for anonymous readers.
 */
static const char *const  ct_bugzilla_cookies[] = {
    "Bugzilla_login=", "Bugzilla_logincookie=", NULL };
static const char *const  ct_bugzilla_uris[] = {
    "/admin.cgi", "/createaccount.cgi", "/relogin.cgi", "/token.cgi",
    "/userprefs.cgi", "/enter_bug.cgi", "/post_bug.cgi",
    "/process_bug.cgi", "/request.cgi", "/quips.cgi", "/votes.cgi",
    "/colchange.cgi", "/summarize_time.cgi", "/sanitycheck.cgi",
    "/page.cgi", "/search_plugin.cgi", "/jsonrpc.cgi", "/xmlrpc.cgi",
    "/rest", "/rest.cgi", "/editclassifications.cgi", "/editcomponents.cgi",
    "/editfields.cgi", "/editflagtypes.cgi", "/editgroups.cgi",
    "/editkeywords.cgi", "/editmilestones.cgi", "/editparams.cgi",
    "/editproducts.cgi", "/editsettings.cgi", "/editusers.cgi",
    "/editvalues.cgi", "/editversions.cgi", "/editwhines.cgi",
    "/editworkflow.cgi", NULL };
static const char *const  ct_bugzilla_args[] = {
    "Bugzilla_api_key", "api_key", "Bugzilla_api_token", "Bugzilla_token",
    "Bugzilla_login", "Bugzilla_password", "Bugzilla_login_token", "token",
    NULL };

/*
 * MantisBT. The install-selected cookie prefix is prepended to every symbolic
 * cookie name, so predicates match the invariant suffix. STRING_COOKIE is the
 * login token; the project/list/collapse cookies change a public render and are
 * conservatively bypassed instead of keyed. Mantis form tokens lazily start a
 * native PHP session for anonymous form pages; PHPSESSID is therefore included
 * too (session.name overrides need an operator rule, documented in the guide).
 */
static const ngx_http_cache_turbo_cookie_pred_t  ct_mantisbt_preds[] = {
    { "_STRING_COOKIE", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { "_PROJECT_COOKIE", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { "_VIEW_ALL_COOKIE", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { "_BUG_LIST_COOKIE", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { "_collapse_settings", NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, NULL },
    { NULL, 0, NULL }
};
static const char *const  ct_mantisbt_cookies[] = { "PHPSESSID=", NULL };
static const char *const  ct_mantisbt_uris[] = {
    "/admin/", "/api/", "/login.php", "/login_page.php",
    "/login_password_page.php", "/logout_page.php", "/signup.php",
    "/signup_page.php", "/lost_pwd.php", "/lost_pwd_page.php",
    "/verify.php", "/verify_email.php", "/my_view_page.php",
    "/account_page.php", "/account_prefs_page.php",
    "/account_prof_edit_page.php", "/account_manage_columns_page.php",
    "/api_tokens_page.php", "/bug_report.php", "/bug_report_page.php",
    "/bug_update.php", "/bug_update_page.php",
    "/bug_change_status_page.php", "/bug_actiongroup_page.php",
    "/bug_actiongroup_ext_page.php", "/bug_reminder_page.php",
    "/bugnote_add.php", "/bugnote_edit_page.php", "/proj_doc_add_page.php",
    "/proj_doc_edit_page.php", "/news_edit_page.php", "/query_store.php",
    NULL };
static const char *const  ct_mantisbt_args[] = { NULL };

/*
 * Plone. __ac is the stable frontend authentication cookie. Zope sessions,
 * status messages and the language override are user-specific state too. Plone
 * itself marks login/reset responses private; the URI tier is still valuable
 * when an operator weakens origin Cache-Control. Traversal views below content
 * (folder/@@edit) remain protected by the auth cookie.
 */
static const char *const  ct_plone_cookies[] = {
    "__ac=", "_ZopeId=", "statusmessages=", "I18N_LANGUAGE=", NULL };
static const char *const  ct_plone_uris[] = {
    "/login", "/logout", "/register", "/passwordreset", "/mail_password",
    "/manage", "/@@login", NULL };
static const char *const  ct_plone_args[] = { NULL };

/*
 * Umbraco. Verified current identity channels include the configurable
 * back-office cookie (default UMB_UCONTEXT), v17+ token cookies, preview/XSRF
 * cookies, and ASP.NET Identity's member cookie. UMB_EXTLOGIN and UMB_SESSION
 * remain conservative compatibility guards for legacy/optional integrations.
 * /umbraco contains the back office and management API; ordinary content and
 * the public Delivery API are left available for caching. Sites that rename
 * the member/back-office cookies must add their configured names explicitly
 * (see docs/umbraco.md).
 */
static const char *const  ct_umbraco_cookies[] = {
    "UMB_UCONTEXT=", "UMB_EXTLOGIN=", "UMB_PREVIEW=",
    "UMB-WEBSITE-PREVIEW-ACCEPT=", "UMB-XSRF-V=", "UMB_SESSION=",
    "umbAccessToken", "umbRefreshToken", "umbPkceCode",
    ".AspNetCore.Identity.Application=", NULL };
static const char *const  ct_umbraco_uris[] = { "/umbraco", NULL };
static const char *const  ct_umbraco_args[] = { NULL };

/*
 * Dotclear. The public frontend does not start the configured PHP session by
 * default; the backend does. `dcxd` is DC_SESSION_NAME's stock value and also
 * prefixes per-blog frontend sessions. dc_admin is the fixed remember-cookie,
 * while dc_passwd grants access to password-protected posts/pages. Preview
 * routes expose unpublished content on the public host. DC_SESSION_NAME and
 * DC_ADMIN_URL are configurable, so non-default deployments need matching
 * operator rules (see docs/dotclear.md).
 */
static const char *const  ct_dotclear_cookies[] = {
    "dcxd", "dc_admin=", "dc_passwd=", NULL };
static const char *const  ct_dotclear_uris[] = {
    "/admin", "/preview", "/pagespreview", NULL };
static const char *const  ct_dotclear_args[] = { NULL };

/*
 * Wiki.js 2.x. Authentication is a fixed `jwt` cookie. Express-session is
 * installed globally but saveUninitialized=false leaves ordinary guests
 * cookie-free; OAuth strategies can create the default connect.sid session.
 * loginRedirect carries a private target across login. The URI tier keeps
 * identity, editor/history/source, upload and GraphQL surfaces out even before
 * a cookie exists. Published arbitrary-path pages remain available for shared
 * guest caching; their ACL/navigation view is guest-group-specific, while all
 * authenticated group variants carry jwt and bypass.
 */
static const char *const  ct_wikijs_cookies[] = {
    "jwt=", "connect.sid=", "loginRedirect=", NULL };
static const char *const  ct_wikijs_uris[] = {
    "/a", "/d", "/e", "/h", "/p", "/s", "/u",
    "/login", "/logout", "/register", "/verify", "/login-reset",
    "/graphql", "/graphql-subscriptions", NULL };
static const char *const  ct_wikijs_args[] = { NULL };

/*
 * Redmine. `_redmine_session` is a hardcoded string literal in
 * config/application.rb (config.session_store :cookie_store, :key =>
 * '_redmine_session') — not derived from config, unlike most of the apps
 * researched alongside it. `autologin` is the remember-me cookie; its name is
 * config-settable (Redmine::Configuration['autologin_cookie_name']) but falls
 * back to the literal, so the stock name is matched and a renamed one degrades
 * to "session cookie still catches an active login" rather than to nothing.
 *
 * The ARG tier is load-bearing here and is NOT optional. `key` authenticates
 * with NO cookie at all: application_controller.rb accepts it as an Atom key
 * (params[:format] == 'atom' && params[:key] -> User.find_by_atom_key) and as
 * an API key (api_key_from_request when Setting.rest_api_enabled?). A
 * cookie-only rule would therefore cache a private issue list fetched via
 * ?key=<atom key> under the public cache key and serve it to everyone. This is
 * the same class of hole the ghost preset's ?uuid=/?key=/?gift= rows close.
 *
 * The URI tier deliberately does NOT list /projects, /issues, /news, /wiki or
 * /repository. On an open tracker those are the main public content and the
 * entire reason to cache it; public-vs-private there is a per-project ACL that
 * nginx cannot see, and the cookie rule is what protects a logged-in view of
 * them. Verified against redmine/redmine master (7.0.0 current 2026-07-26).
 */
static const char *const  ct_redmine_cookies[] = {
    "_redmine_session=", "autologin=", NULL };
static const char *const  ct_redmine_uris[] = {
    "/admin", "/my", "/login", "/logout", "/account",
    "/settings", "/enumerations", "/roles", "/trackers", "/custom_fields",
    "/auth_sources", "/mail_handler", NULL };
static const char *const  ct_redmine_args[] = { "key", NULL };

/*
 * Flarum. The cookie tier matches ONLY `flarum_remember`, never
 * `flarum_session` — and that distinction is the whole preset.
 * Http/Middleware/StartSession.php applies withSessionCookie() unconditionally
 * after $session->save(), on every response, before any auth check, so
 * `flarum_session` is issued to ANONYMOUS GUESTS. A rule matching it would fire
 * on ~100% of traffic and silently disable the cache — the guest-issued-cookie
 * trap this registry's header comment forbids. `flarum_remember` is written
 * only by Http/Rememberer.php (COOKIE_NAME = 'remember'), i.e. at login.
 *
 * KNOWN GAP, documented rather than papered over: a user who logs in WITHOUT
 * "remember me" carries only `flarum_session`, whose guest and member forms are
 * distinguishable solely by the session id's server-side mapping. nginx cannot
 * tell them apart, so such a login is invisible to the cookie tier. /api is in
 * the URI tier partly to contain that — the SPA fetches its content through it —
 * but a non-remembered login browsing plain discussion URLs is genuinely
 * unprotected by this preset alone. docs/flarum.md prescribes the map-based
 * rule for sites that need to close it.
 *
 * Both names carry the `cookie.name` prefix from config.php (CookieFactory.php:
 * $prefix = $config['cookie.name'] ?? 'flarum', getName() returns
 * "{$prefix}_{$name}"), and `paths.admin`/`paths.api` are renameable the same
 * way; all three are matched at their stock values only. Verified against
 * flarum/framework main (2.0.0-rc.5; identical mechanics in the 1.8.x stable
 * line).
 */
static const char *const  ct_flarum_cookies[] = {
    "flarum_remember=", NULL };
static const char *const  ct_flarum_uris[] = {
    "/admin", "/api", "/login", "/logout", "/global-logout", "/register",
    "/reset", "/confirm", "/settings", "/notifications", NULL };
static const char *const  ct_flarum_args[] = { NULL };

/*
 * OpenCart. This preset is ARG-tier, not URI-tier, and that is forced by the
 * application: OpenCart routes everything through index.php?route=<controller>,
 * so every private page shares the single path /index.php. A URI-prefix rule
 * catches NOTHING here — it would look correct, match nothing, and leave carts
 * and account pages cacheable. The `route=account/` and `route=checkout/`
 * prefixes cover the whole private surface (verified against
 * upload/catalog/controller/{account,checkout}/ on opencart/opencart master,
 * 4.1.0.3 current 2026-07-26). `user_token` is the admin-panel auth arg and
 * `customer_token` the login-validation token.
 *
 * NO COOKIE ROW, deliberately. `OCSESSID` (upload/system/config/default.php,
 * $_['session_name']) is issued to guests — a shop has to track an anonymous
 * cart — and login state lives in $this->session->data['customer'], SERVER-SIDE
 * ONLY. The cookie value is an opaque session id whose guest and customer forms
 * are identical on the wire, so there is nothing for nginx to test. Adding
 * `OCSESSID` here would bypass every visitor and disable the cache. The
 * /admin/ path is renameable at install and is therefore left to the operator.
 *
 * The route values are ENUMERATED, not prefix-matched. The arg tier compares
 * NAME=VALUE by exact bytes (see the NAME=VALUE branch in auto_skip: "no case
 * folding, no prefix match"), so a `route=account/` row would match only the
 * literal ?route=account/ and never ?route=account/login — i.e. it would look
 * right and protect nothing. Every private route is therefore listed in full.
 * ADDING A ROUTE MEANS ADDING A ROW; a new private controller under
 * account/ or checkout/ is NOT covered automatically.
 *
 * No key_cookies: OpenCart 4.x drives language and currency through the URL
 * (catalog/controller/common/language.php only reads request/config and
 * redirects with the arg — it sets no cookie), so there is no rendering cookie
 * to vary on. The 3.x-era `language`/`currency` cookies were checked for and
 * are NOT set by 4.x; do not add them back without re-verifying.
 */
static const char *const  ct_opencart_cookies[] = { NULL };
static const char *const  ct_opencart_uris[] = { NULL };
static const char *const  ct_opencart_args[] = {
    "route=checkout/cart", "route=checkout/checkout", "route=checkout/confirm",
    "route=checkout/success", "route=checkout/failure",
    "route=checkout/payment_address", "route=checkout/payment_method",
    "route=checkout/shipping_address", "route=checkout/shipping_method",
    "route=checkout/register",
    "route=account/account", "route=account/login", "route=account/logout",
    "route=account/register", "route=account/forgotten", "route=account/edit",
    "route=account/password", "route=account/address", "route=account/order",
    "route=account/wishlist", "route=account/download", "route=account/returns",
    "route=account/reward", "route=account/transaction",
    "route=account/subscription", "route=account/newsletter",
    "route=account/affiliate", "route=account/custom_field",
    "route=account/tracking", "route=account/payment_method",
    "route=account/authorize", "route=account/success",
    "user_token", "customer_token", NULL };

const ngx_http_cache_turbo_preset_t  ngx_http_cache_turbo_presets[] = {
    { NGX_HTTP_CACHE_TURBO_BACKEND_WORDPRESS,
      ct_wp_cookies, ct_wp_uris, ct_wp_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_WOOCOMMERCE,
      ct_woo_cookies, ct_woo_uris, ct_woo_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_JOOMLA,
      ct_joomla_cookies, ct_joomla_uris, ct_joomla_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_XENFORO,
      ct_xf_cookies, ct_xf_uris, ct_xf_args, NULL, ct_xf_key_cookies },
    { NGX_HTTP_CACHE_TURBO_BACKEND_DISCOURSE,
      ct_discourse_cookies, ct_discourse_uris, ct_discourse_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_PHPBB,
      ct_phpbb_cookies, ct_phpbb_uris, ct_phpbb_args, ct_phpbb_preds, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_DRUPAL,
      ct_drupal_cookies, ct_drupal_uris, ct_drupal_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_MEDIAWIKI,
      ct_mw_cookies, ct_mw_uris, ct_mw_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_MAGENTO,
      ct_magento_cookies, ct_magento_uris, ct_magento_args, NULL,
      ct_magento_key_cookies },
    { NGX_HTTP_CACHE_TURBO_BACKEND_GHOST,
      ct_ghost_cookies, ct_ghost_uris, ct_ghost_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_WAGTAIL,
      ct_wagtail_cookies, ct_wagtail_uris, ct_wagtail_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_KIRBY,
      ct_kirby_cookies, ct_kirby_uris, ct_kirby_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_SHOPWARE6,
      ct_shopware6_cookies, ct_shopware6_uris, ct_shopware6_args, NULL,
      ct_shopware6_key_cookies },
    { NGX_HTTP_CACHE_TURBO_BACKEND_TYPO3,
      ct_typo3_cookies, ct_typo3_uris, ct_typo3_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_INVISION,
      ct_invision_cookies, ct_invision_uris, ct_invision_args,
      ct_invision_preds, ct_invision_key_cookies },
    { NGX_HTTP_CACHE_TURBO_BACKEND_SMF,
      ct_smf_cookies, ct_smf_uris, ct_smf_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_VANILLA,
      ct_vanilla_cookies, ct_vanilla_uris, ct_vanilla_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_PUNBB,
      ct_punbb_cookies, ct_punbb_uris, ct_punbb_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_PHORUM,
      ct_phorum_cookies, ct_phorum_uris, ct_phorum_args, NULL,
      ct_phorum_key_cookies },
    { NGX_HTTP_CACHE_TURBO_BACKEND_YABB,
      ct_yabb_cookies, ct_yabb_uris, ct_yabb_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_MYBB,
      ct_mybb_cookies, ct_mybb_uris, ct_mybb_args, ct_mybb_preds,
      ct_mybb_key_cookies },
    { NGX_HTTP_CACHE_TURBO_BACKEND_VBULLETIN,
      ct_vbulletin_cookies, ct_vbulletin_uris, ct_vbulletin_args,
      ct_vbulletin_preds, ct_vbulletin_key_cookies },
    { NGX_HTTP_CACHE_TURBO_BACKEND_TEXTPATTERN,
      ct_textpattern_cookies, ct_textpattern_uris, ct_textpattern_args,
      NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_BLUDIT,
      ct_bludit_cookies, ct_bludit_uris, ct_bludit_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_SPIP,
      ct_spip_cookies, ct_spip_uris, ct_spip_args, ct_spip_preds, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_BUGZILLA,
      ct_bugzilla_cookies, ct_bugzilla_uris, ct_bugzilla_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_MANTISBT,
      ct_mantisbt_cookies, ct_mantisbt_uris, ct_mantisbt_args,
      ct_mantisbt_preds, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_PLONE,
      ct_plone_cookies, ct_plone_uris, ct_plone_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_UMBRACO,
      ct_umbraco_cookies, ct_umbraco_uris, ct_umbraco_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_DOTCLEAR,
      ct_dotclear_cookies, ct_dotclear_uris, ct_dotclear_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_WIKIJS,
      ct_wikijs_cookies, ct_wikijs_uris, ct_wikijs_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_REDMINE,
      ct_redmine_cookies, ct_redmine_uris, ct_redmine_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_FLARUM,
      ct_flarum_cookies, ct_flarum_uris, ct_flarum_args, NULL, NULL },
    { NGX_HTTP_CACHE_TURBO_BACKEND_OPENCART,
      ct_opencart_cookies, ct_opencart_uris, ct_opencart_args, NULL, NULL },
    { 0, NULL, NULL, NULL, NULL, NULL }
};
/* >>> FUZZ-EXTRACT auto-classify END (presets.c portion) <<< */

#pragma GCC visibility pop
