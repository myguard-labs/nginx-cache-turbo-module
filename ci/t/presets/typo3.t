# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# TYPO3 preset (docs/typo3.md). Ported from test_typo3_preset() in
# ci/tools/test_runtime.py.
#
# LAZY SESSIONS, CONFIRMED AT THE STRONGEST POSSIBLE PLACE
# ----------------------------------------------------------------------------
# TYPO3's frontend authentication object opts OUT of cookies by default:
# FrontendUserAuthentication::$dontSetCookie = true (:155) OVERRIDES the base
# class default of false (AbstractUserAuthentication:199), and it is flipped
# back to false in exactly two places, both on the login path --
# createUserSession() (:242) and regenerateSessionId() (:407), gated by
# shallSetSessionCookie() (:344). So an anonymous visitor reading public pages
# is issued NO cookie at all. That is a deliberate upstream decision in favour
# of caching, not an accident this preset happens to exploit. TEST 8 pins it.
#
# THE ONE CAVEAT, AND IT IS A REAL ONE
# ----------------------------------------------------------------------------
# fe_typo_user is admin-overridable, not a hard literal:
# FrontendUserAuthentication::getCookieName() (:167) reads
# $GLOBALS['TYPO3_CONF_VARS']['FE']['cookieName'] and falls back to
# 'fe_typo_user'. It is a plain default rather than a per-install hash (unlike
# Drupal's SESS<hash> or Grav's grav-site-<hash>), and overriding it is rare --
# but a site that DOES override it silently loses the match, and a lost match on
# a BYPASS rule means logged-in pages get cached. docs/typo3.md tells such a site
# to add its own name with cache_turbo_bypass_cookie. The preset matches the
# default exactly; it cannot match a name it cannot know.
#
# be_typo_user IS NOT REDUNDANT WITH THE FE COOKIE
# ----------------------------------------------------------------------------
# It is a genuine stable literal, and it covers a different leak: an editor
# previewing the frontend, or any backend user hitting a FE page, carries ONLY
# the BE cookie, and TYPO3 renders hidden/scheduled records and preview versions
# for them. Caching that response publishes unpublished content to strangers.
# Same class as xenforo's xf_session_admin -- a second cookie, a second
# lifetime. TEST 3 sends each cookie ALONE precisely so that dropping either
# literal from ct_typo3_cookies[] goes red on its own row; a combined-only test
# would stay green with one of the two deleted.
#
# "/typo3" IS SLASH-LESS -- THE SEGMENT-TERMINATION BRANCH IS LIVE HERE
# ----------------------------------------------------------------------------
# ct_typo3_uris[] is { "/typo3" } with no boundary of its own, so
# ngx_http_cache_turbo_uri_prefix() runs past its `pfx[l-1] == '/'`
# short-circuit and reaches the real trailing-byte check: the byte after the
# needle must be '/' or '.' or the URI must end there. TEST 2 is therefore the
# classic segment-termination oracle rather than a byte-0 anchor substitute --
# "/typo3-guide" shares the prefix but continues with '-', a different path
# segment, and must CACHE. Relax the boundary check to a bare prefix test and
# TEST 2 goes red. TEST 1 covers the other two arms of the same function: an
# exact match ("/typo3", uri->len == l) and a '/'-terminated continuation
# ("/typo3/module/web/layout").
#
# The /typo3 entry point is stable -- TYPO3 does not randomise it the way
# magento randomises /admin -- so there is no per-install-path caveat here.
#
# NO ARGS, NO KEY COOKIES, NO PREDICATES -- ct_typo3_args[] is { NULL }, and the
# typo3 row in ngx_http_cache_turbo_presets[] carries NULL for both cookie_preds
# and key_cookies. This file therefore has no arg leg, no predicate leg and no
# value-keying leg. Only the URI and cookie-bypass legs apply.
#
# See ci/t/presets/xenforo.t for why every bypass case is fetched TWICE (a
# bypass and a first-time MISS both lack X-Cache, so a single fetch proves
# nothing) and why these are `--- request eval` arrays rather than
# `--- pipelined_requests`.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

# The preset's URI rule is a prefix anchored at byte 0, so it gets its own ROOT
# location -- without a real location nginx's implicit 404 also carries no
# X-Cache and a "must bypass" assertion would pass for free.
#
# /typo3-guide is its own ROOT location and is the segment-termination control:
# it must be genuinely routable and cacheable, or TEST 2 would pass on a 404
# rather than on the boundary check.
#
# /t3/ is the public frontend surface, carrying the cookie cases.
# /gen/ is the isolation control -- a DIFFERENT preset.
our $Config = ct_config(
    { path => '/typo3',       backend => 'typo3' },
    { path => '/typo3-guide', backend => 'typo3' },
    { path => '/t3/',         backend => 'typo3' },
    { path => '/gen/',        backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: the /typo3 backend bypasses, exact and sub-path
# Two distinct arms of ngx_http_cache_turbo_uri_prefix(): "/typo3" exactly
# (uri->len == l, the early `return 1`) and "/typo3/module/web/layout" (a
# '/'-terminated continuation, the trailing-byte check). Fetched twice each
# because a bypass and a first-time MISS are indistinguishable from one fetch --
# both lack X-Cache.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /typo3", "GET /typo3",
 "GET /typo3/module/web/layout", "GET /typo3/module/web/layout"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 2: SEGMENT BOUNDARY -- /typo3-guide must CACHE
# This preset's engine-mutation oracle: "/typo3" carries no trailing '/', so the
# boundary branch of ngx_http_cache_turbo_uri_prefix() is LIVE. The byte after
# the needle here is '-', not '/' or '.' and not end-of-URI, so /typo3-guide is
# a different path segment -- a public documentation page that merely shares the
# prefix -- and must cache.
#
# Relax the boundary check to a bare prefix test (make the function return 1 as
# soon as the prefix matches) and this test goes red. Sent under its own REAL
# location so the HIT assertion cannot pass for free on an implicit 404.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /typo3-guide", "GET /typo3-guide"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 3: each identity cookie bypasses ON ITS OWN
# ct_typo3_cookies[] holds two literals with two different leaks, so each is
# sent ALONE: fe_typo_user is the frontend login cookie (a member's personalised
# page), be_typo_user is the backend one (an editor previewing hidden and
# scheduled records). Dropping either literal from the table must go red on its
# OWN row -- a combined-cookie-only test would stay green with one of the two
# deleted, which is exactly the shape of leak this preset exists to prevent.
# Sent on a public URL a guest can also fetch, so each bypass is attributable to
# the cookie and not to the path.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /t3/page-a", "GET /t3/page-a",
 "GET /t3/page-b", "GET /t3/page-b",
 "GET /t3/page-c", "GET /t3/page-c"]
--- more_headers eval
["Cookie: fe_typo_user=abc123",
 "Cookie: fe_typo_user=abc123",
 "Cookie: be_typo_user=def456",
 "Cookie: be_typo_user=def456",
 "Cookie: fe_typo_user=abc123; be_typo_user=def456",
 "Cookie: fe_typo_user=abc123; be_typo_user=def456"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 4: a suffix-bearing cookie under ANY prefix still bypasses
# The bypass predicate matches the cookie NAME by suffix, so a proxy- or
# CDN-prefixed variant of either identity cookie is still a login signal. If
# this were an exact-name match instead, a site behind a cookie-rewriting edge
# would serve editor and member HTML from the shared bucket. Both cookies are
# covered because they are two independent table entries.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /t3/page-d", "GET /t3/page-d",
 "GET /t3/page-e", "GET /t3/page-e"]
--- more_headers eval
["Cookie: __Secure-fe_typo_user=abc123",
 "Cookie: __Secure-fe_typo_user=abc123",
 "Cookie: __Host-be_typo_user=def456",
 "Cookie: __Host-be_typo_user=def456"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 5: empty-valued and bare valueless session cookies still bypass
# A just-logged-out user is commonly served `fe_typo_user=` (an expiry-style
# clear) before the browser drops it, and a trimmed or malformed Cookie header
# may carry the bare name with no '=' at all. The predicate is NONEMPTY on the
# NAME, not on the value, so presence of the name is enough in both shapes.
# Pinned because an implementation that required a non-empty value would open a
# window where a logout-in-progress request is served from -- and populates --
# the shared bucket.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /t3/page-k", "GET /t3/page-k",
 "GET /t3/page-l", "GET /t3/page-l"]
--- more_headers eval
["Cookie: fe_typo_user=",
 "Cookie: fe_typo_user=",
 "Cookie: be_typo_user",
 "Cookie: be_typo_user"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 6: a matching cookie must not end the cookie scan
# The identity cookie sits FIRST and an unrelated cookie follows. A scanner that
# returned early on its first match would still bypass here, so the
# load-bearing half is the reverse order below: an unrelated cookie first, the
# identity cookie second. Both orders are sent so a regression in either
# direction is visible.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /t3/page-m", "GET /t3/page-m",
 "GET /t3/page-n", "GET /t3/page-n"]
--- more_headers eval
["Cookie: fe_typo_user=abc; _ga=GA1.2.3",
 "Cookie: fe_typo_user=abc; _ga=GA1.2.3",
 "Cookie: _ga=GA1.2.3; be_typo_user=def",
 "Cookie: _ga=GA1.2.3; be_typo_user=def"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 7: an unrelated query arg still caches
# ct_typo3_args[] is { NULL } -- typo3 has NO arg rows at all. TYPO3's own
# cHash/id/type parameters are deliberately absent: they select which page is
# rendered, and the cache key already carries $uri and $args, so keying on them
# again would be redundant while BYPASSING on them would take every internal
# link off cache. A campaign-tagged URL must therefore cache like any other.
# Pinned because an engine that treated an empty arg table as "match
# everything" rather than "match nothing" would take the whole site off cache,
# and no other test in this file would catch it.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /t3/page-f?utm_source=twitter", "GET /t3/page-f?utm_source=twitter"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 8: an anonymous reader of the frontend CACHES
# The whole reason the preset ships, and the property the $dontSetCookie
# analysis at the top of this file establishes: an anonymous reader of a public
# TYPO3 page is issued no cookie at all. If this went red the preset would be
# caching nothing and every bypass test above would pass vacuously. The
# unrelated-cookie case is the negative half of TEST 3 -- the cookie list is not
# "any cookie at all", or one analytics cookie would take the whole site off
# cache.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /t3/home", "GET /t3/home",
 "GET /t3/page-p", "GET /t3/page-p"]
--- more_headers eval
["", "",
 "Cookie: _ga=GA1.2.3.4",
 "Cookie: _ga=GA1.2.3.4"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]



=== TEST 9: the typo3 rows do not leak into another backend's location
# /gen/ runs the wordpress preset. The typo3 URI and cookie rules are opt-in per
# location; if the registry ORed every preset's rows together instead of
# selecting by bit, these would bypass here too. Both legs are exercised: a
# cookie row, and the URI row nested under /gen/.
#
# NOTE the cookie leg is a REAL cross-preset case, not a tautology: wordpress
# has its own cookie list and neither "fe_typo_user" nor "be_typo_user" is on
# it.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /gen/page-a", "GET /gen/page-a",
 "GET /gen/typo3/module", "GET /gen/typo3/module"]
--- more_headers eval
["Cookie: fe_typo_user=abc123",
 "Cookie: fe_typo_user=abc123",
 "", ""]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]
