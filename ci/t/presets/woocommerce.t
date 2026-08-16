# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# WooCommerce preset (docs/woocommerce.md). New port -- no prior Python test
# existed for this preset in ci/tools/test_runtime.py.
#
# `ct_woo_cookies[]` = woocommerce_items_in_cart, woocommerce_cart_hash,
#                       wp_woocommerce_session_
# `ct_woo_uris[]`    = /cart, /checkout, /my-account
# `ct_woo_args[]`    = wc-ajax
#
# Like wordpress.t, this preset is bypass-only (cookie_preds = NULL,
# key_cookies = NULL in the ngx_http_cache_turbo_backends[] registry row), so
# it has no value-predicate leg and no value-keying leg -- every cookie row is
# PRESENCE-ONLY, matched via ngx_http_cache_turbo_cookie_has(), which is a
# bounded SUBSTRING search over the raw Cookie header VALUE, not a
# suffix-of-name match against a parsed cookie name -- that stricter
# name_has_suffix() matcher belongs to the separate value-predicate tier
# (cookie_preds, tier 2), which this preset's registry row does not use. Same
# engine and same distinction as wordpress.t's ct_wp_cookies[].
#
# THE THREE URI SLUGS ARE ENGLISH DEFAULTS, NOT CONSTANTS -- DO NOT TRUST THEM
# ------------------------------------------------------------------------
# Verbatim from the ct_woo_uris[] header comment in src, because it is the
# whole reason this preset cannot stand alone:
#
#   THESE THREE SLUGS ARE ENGLISH DEFAULTS, NOT CONSTANTS, and on a
#   non-English store they match NOTHING. WC_Install::create_pages() declares
#   them as TRANSLATABLE strings -- _x( 'cart', 'Page slug', 'woocommerce' ) --
#   and wraps the whole page-creation block in wc_switch_to_site_locale()
#   precisely so that "pages are created in the correct language". So a German
#   store gets /warenkorb, /kasse, /mein-konto AT INSTALL TIME, by design.
#   This is not admin drift that a careful operator avoids; it is the shipped
#   behaviour for every locale but one. An admin can also rename the pages
#   afterwards, and the `woocommerce_create_pages` filter can replace the set
#   outright.
#
#   So DO NOT TREAT THE URI TIER AS THE GUARD HERE. It is a convenience for
#   the default-locale majority. What actually holds on a translated store is
#   the cookie tier above plus the STACKED wordpress preset -- a logged-in
#   customer carries wordpress_logged_in_, and a shopper with a cart carries
#   woocommerce_items_in_cart / wp_woocommerce_session_.
#
#   That stacking is not optional, and this is the case that proves it: a
#   `cache_turbo_backend woocommerce;` used ALONE on a translated store serves
#   a logged-in customer with an EMPTY cart -- no woo cookie, no URI match, no
#   wordpress preset -- a CACHED /mein-konto. Every WooCommerce doc says to
#   stack `wordpress woocommerce`; this is why.
#
# `cache_turbo_backend woocommerce;` alone silently implies `wordpress` too
# (ngx_http_cache_turbo_expand_implies(), the "woocommerce -> wordpress"
# fixpoint expansion at registry setup) -- so the composition is not something
# an operator can forget by typing just "woocommerce"; TEST 8 pins that this
# stacking is live: a bare wordpress_logged_in_ cookie (no woo cookie at all)
# must bypass under a location configured with ONLY `cache_turbo_backend
# woocommerce;`.
#
# wc-ajax IS LOAD-BEARING -- NO URI PREFIX CAN SUBSTITUTE FOR IT
# ------------------------------------------------------------------------
# Verbatim from the ct_woo_args[] header comment in src:
#
#   wc-ajax is LOAD-BEARING, not decoration -- it is the one WooCommerce rule
#   that no URI prefix can substitute for. WC's AJAX endpoints do not live
#   under a path of their own: they ride on WHATEVER page the shopper is on,
#   as a query arg (includes/class-wc-ajax.php::get_endpoint() ->
#   "currentpageurl?wc-ajax=name"). So `/?wc-ajax=get_refreshed_fragments` is
#   a request to the CACHED HOME PAGE, and none of /cart, /checkout,
#   /my-account match it.
#
#   The response is that shopper's cart-fragment HTML. Store it and the next
#   visitor is served someone else's cart. This is the only cross-customer
#   leak path the URI rules cannot close, which is why it is an ARG rule.
#
# TEST 6 fires wc-ajax on a NON-woo path (the home page, not /cart) --
# that is the entire point of the rule, and a test that only ever hit
# wc-ajax under /cart would leave the URI-independence unverified.
#
# THE wp_woocommerce_session_ ROW -- WHY IT STILL MATCHES DESPITE THE HASH
# ------------------------------------------------------------------------
# `wp_woocommerce_session_` reads as a PREFIX in WordPress reality -- the real
# cookie WooCommerce sets is `wp_woocommerce_session_<hash>`, e.g.
# `wp_woocommerce_session_a1b2c3...`, with the hash coming AFTER the needle. A
# NAME-SUFFIX matcher (ngx_http_cache_turbo_name_has_suffix, the tier-2
# value-predicate matcher) would never fire on that: the cookie's name does
# not END in the needle. But this preset's bypass check is
# ngx_http_cache_turbo_cookie_has(), which does a plain SUBSTRING search
# over the raw Cookie header VALUE -- not a suffix check against
# a parsed cookie NAME at all. `wp_woocommerce_session_` is found verbatim
# inside `wp_woocommerce_session_a1b2c3...=...`, so the row DOES fire, and
# TEST 9 is the regression pin for that. Worth pinning precisely because the
# suffix-vs-substring distinction is easy to get backwards -- read
# ct_wp_cookies[] and its sibling ct_woo_cookies[] the same way here as
# wordpress.t does.
#
# See ci/t/presets/xenforo.t for why every bypass case is fetched TWICE (a
# bypass and a first-time MISS both lack X-Cache) and why these are
# `--- request eval` arrays rather than `--- pipelined_requests`.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

# The preset's URI rules are prefixes anchored at byte 0, so /cart,
# /checkout and /my-account must be ROOT locations. /woo/ carries the
# path-independent cookie and arg cases. /woo-solo/ is configured with ONLY
# `cache_turbo_backend woocommerce;` (no explicit wordpress) to prove the
# implied stacking is live. /gen/ is the isolation control -- a DIFFERENT
# preset (drupal, not wordpress -- wordpress would stay green through the
# composition tests even with the woo rows deleted, which would hide vacuity).
our $Config = ct_config(
    { path => '/cart',       backend => 'woocommerce' },
    { path => '/checkout',   backend => 'woocommerce' },
    { path => '/my-account', backend => 'woocommerce' },
    { path => '/woo/',       backend => 'woocommerce' },
    { path => '/woo-solo/',  backend => 'woocommerce' },
    { path => '/gen/',       backend => 'drupal' },
);

run_tests();

__DATA__

=== TEST 1: all three URI rows bypass at the root, with no cookie
# The full ct_woo_uris[] table, each on its own path so a shared key cannot
# mask a missing row.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /cart",       "GET /cart",
 "GET /checkout",   "GET /checkout",
 "GET /my-account", "GET /my-account"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 2: the two positive boundary arms still bypass
# "/cart/" ('/' continuation) and "/cart.php" ('.' continuation) are both
# inside the matched subtree per the segment-termination check.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /cart/",     "GET /cart/",
 "GET /cart.php",  "GET /cart.php"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 3: SEGMENT BOUNDARY NEGATIVE -- /cartoon must CACHE
# "/cart" is slash-less, so the boundary branch of
# ngx_http_cache_turbo_uri_prefix() is LIVE. The byte after the needle here is
# 'o', not '/' or '.' and not end-of-URI, so this is a DIFFERENT path segment
# ("/cartoon") that merely shares the prefix and must cache, not bypass.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /cartoon", "GET /cartoon"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 4: THE VACUOUS URI TEST -- /woo/cart HITs, not byte-0
# uri_prefix() is byte-0 anchored, so a URI test served under a location whose
# path is NOT the root never reaches the rule. This proves a URI arm sent
# under /woo/ would pass for free even with the row deleted -- exactly why
# every URI arm in TEST 1 is sent at the true root instead.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /woo/cart", "GET /woo/cart"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 5: wc-ajax bypasses on a NON-woo path -- its whole point
# WC AJAX endpoints ride on whatever page the shopper is on, as a query arg --
# no URI prefix can substitute for this rule. Fired here on /woo/ (a plain
# content path, not /cart/checkout/my-account) to prove URI-independence.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /woo/home?wc-ajax=get_refreshed_fragments", "GET /woo/home?wc-ajax=get_refreshed_fragments"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 6: an unrelated query arg still caches -- the negative half of TEST 5
# A DISTINCT path from TEST 5 on purpose: cache_turbo_key is $uri, so the two
# blocks shared one cache entry and this MISS-then-HIT held only because TEST 5
# bypasses and stores nothing -- an assertion resting on block order.
# If the arg rule matched on presence of ANY query string, every parameterised
# WooCommerce/WordPress URL would bypass and the cache would be off site-wide.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /woo/home-utm?utm_source=twitter", "GET /woo/home-utm?utm_source=twitter"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 7: member LEAK GUARD -- each real woo cookie bypasses, leading
# non-matching cookie included so a scan that stops at the first pair cannot
# pass this vacuously. woocommerce_items_in_cart and woocommerce_cart_hash are
# fixed literal names (no hash suffix), unlike the wp_woocommerce_session_ row
# covered separately in TEST 9.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers eval
["Cookie: unrelated=1; woocommerce_items_in_cart=1",
 "Cookie: unrelated=1; woocommerce_items_in_cart=1",
 "Cookie: unrelated=1; woocommerce_cart_hash=abc123",
 "Cookie: unrelated=1; woocommerce_cart_hash=abc123"]
--- request eval
["GET /woo/cart-a", "GET /woo/cart-a",
 "GET /woo/cart-b", "GET /woo/cart-b"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 8: WORDPRESS COMPOSITION -- wordpress_logged_in_ bypasses under a woocommerce-only location
# The case the file header quotes at length: a logged-in customer with an
# EMPTY cart carries no woo cookie and hits no woo URI, so only the STACKED
# wordpress preset closes this leak. `cache_turbo_backend woocommerce;` alone
# silently implies wordpress too (ngx_http_cache_turbo_expand_implies()), so
# /woo-solo/ -- which names ONLY woocommerce in its config -- must still
# bypass on a pure WordPress login signal.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: wordpress_logged_in_abc123=alice|1|deadbeef
--- request eval
["GET /woo-solo/account", "GET /woo-solo/account"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 9: wp_woocommerce_session_ REGRESSION PIN -- the real hashed cookie still bypasses
# The real WooCommerce session cookie is
# `wp_woocommerce_session_<hash>` (e.g. `wp_woocommerce_session_a1b2c3d4`),
# with the hash coming AFTER the needle. Despite that, this preset's bypass
# check (ngx_http_cache_turbo_cookie_has) is a SUBSTRING search over the raw
# Cookie header value, not a suffix-of-name check -- the needle
# `wp_woocommerce_session_` is found verbatim inside the real cookie's
# name=value pair, so this DOES bypass. Regression pin for the substring
# behaviour: a change to a stricter name-suffix matcher here would silently
# stop matching this exact real-world cookie.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: wp_woocommerce_session_a1b2c3d4=t1%3Da2b3c4
--- request eval
["GET /woo/session-real", "GET /woo/session-real"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 10: name-under-any-prefix -- a namespaced cart cookie still bypasses
# The match is a SUBSTRING search over the header VALUE, so a proxy- or
# multisite-prefixed variant whose name merely CONTAINS the needle is still a
# cart signal, deliberately the safe-side asymmetry (same shape as
# wordpress.t TEST 13, though that preset's matcher is name-suffix, not
# substring-of-value).
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: mystore_woocommerce_items_in_cart=1
--- request eval
["GET /woo/prefix-cart", "GET /woo/prefix-cart"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 11: an EMPTY cookie value still bypasses -- presence, not NONEMPTY
# No cookie_preds row exists for woocommerce (registry entry carries NULL);
# the rule is presence-of-suffix-matching-name only, so an empty value must
# still bypass -- the fail-CLOSED direction, same shape as wordpress.t TEST 15.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: woocommerce_items_in_cart=
--- request eval
["GET /woo/empty-val", "GET /woo/empty-val"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 12: a bare valueless cookie (no '=') also bypasses
# Same presence-only reasoning as TEST 11, at the other malformed edge: no '='
# at all. An unparseable cookie must never be assumed a guest -- fails closed.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: woocommerce_items_in_cart
--- request eval
["GET /woo/bare-cookie", "GET /woo/bare-cookie"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 13: a cookieless request caches
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /woo/no-cookie", "GET /woo/no-cookie"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 14: isolation -- the woo cart cookie under /gen/ (drupal backend) still HITs
# drupal has its own cookie list and the woocommerce rows do not leak across
# backends. drupal, not wordpress, is deliberately chosen here: wordpress would
# stay green through this test even with every woo row deleted, because
# wordpress carries no woo cookie/URI/arg rows of its own to confuse with --
# drupal proves true preset isolation instead of accidentally re-testing the
# composition case from TEST 8.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: woocommerce_items_in_cart=1
--- request eval
["GET /gen/topic-iso", "GET /gen/topic-iso"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
