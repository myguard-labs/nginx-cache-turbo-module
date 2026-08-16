# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Vanilla preset (docs/vanilla.md). Ported from the sole test in
# ci/tools/test_runtime.py, deleted by this port:
# test_vanilla_guest_cookies_stay_cacheable(), its `location /vanilla/`
# fixture (used by nothing else), and its call in run_all().
#
# THE IDENTITY COOKIE, AND WHY THE TRAILING '=' IS LOAD-BEARING
# ------------------------------------------------------------------------
# Verbatim from the ct_vanilla_cookies[] header comment in src:
#
#   Vanilla Forums. The `Vanilla` identity cookie (Gdn_CookieIdentity::
#   SetIdentity()) is written ONLY at login/SSO time -- a true guest never
#   receives it at all, unlike the phpBB/SMF/XenForo shape. No value
#   predicate is needed or available (the value is an HMAC-signed opaque
#   payload).
#
#   CAVEAT: this is corroborated via Vanilla's own KB article and community
#   threads describing SetIdentity/GetIdentity, not a direct line-cited
#   GitHub source read (the exact file could not be fetched at research
#   time -- it may have moved in the TypeScript/PHP8 rewrite of newer
#   Vanilla). Ship it, but verify empirically against your own install
#   (curl anonymously, confirm no `Set-Cookie: Vanilla=...` appears) before
#   relying on it in production.
#
#   The rule matches "Vanilla=" -- the identity cookie's name followed by
#   its delimiter -- NOT the bare substring "Vanilla". Vanilla derives
#   several GUEST-issued cookie names from the same `Garden.Cookie.Name`
#   prefix (`Vanilla-tk`, the CSRF transient key, and `Vanilla-Vv`, the
#   visit tracker), so a bare-prefix match would fire on ordinary anonymous
#   traffic and collapse the hit rate to cookieless first hits and
#   crawlers -- the guest-issued-cookie trap this registry's header comment
#   forbids. The trailing '=' is what separates the identity cookie from its
#   siblings.
#
#   Renaming `Garden.Cookie.Name` therefore defeats this rule; docs/vanilla.md
#   tells the operator to add their own cache_turbo_bypass in that case.
#
# TESTS 5-6 are the ported test_vanilla_guest_cookies_stay_cacheable: BOTH
# directions asserted -- Vanilla-tk / Vanilla-Vv guest cookies stay
# cacheable, and the real `Vanilla=` identity cookie still bypasses. TEST 7
# is the suffix-under-any-prefix leg the registry's cookie_preds engine
# implies (ngx_http_cache_turbo_cookie_has() scans for a substring anywhere in the
# Cookie header, not an anchored match): `MyVanilla=` also bypasses.
#
# NO /api ROW, DELIBERATELY, AND THIS IS AN UNRESOLVED GAP
# ------------------------------------------------------------------------
# Verbatim from the ct_vanilla_uris[] header comment in src:
#
#   NO /api ROW, DELIBERATELY, and this is an unresolved gap rather than a
#   decision. Vanilla's API v2 is Bearer-authenticated, so it is exactly the
#   header-auth surface the cookie tier cannot see -- the same class as
#   magento /rest, drupal /jsonapi and xenforo /api/, all of which ARE
#   listed.
#
#   It is not listed here because it cannot be verified: github.com/vanilla/
#   vanilla now 404s (repo, raw and API alike; the org survives), so there is
#   no upstream tree left to check the prefix against, and every surviving
#   reference is a Garden-era fork last pushed in 2013. Adding a row from
#   recollection is exactly what produced the dead /admin.php and
#   /message_send.php rows in punbb, so it is not being done. An operator
#   running Vanilla's API adds their own:
#       cache_turbo_bypass_uri /api;
#   See docs/vanilla.md.
#
# ct_vanilla_args[] is { NULL } and the preset row carries NULL in both
# cookie_preds and key_cookies, so this file has no arg leg, no predicate
# leg, and no value-keying leg. No row is a prefix of another row
# ("/dashboard", "/entry/", "/messages/", "/post/" -- checked pairwise), so
# the #222 prefix-row rule does not apply here.
#
# "/dashboard" IS SLASH-LESS -- THE SEGMENT-TERMINATION BRANCH IS LIVE HERE
# ------------------------------------------------------------------------
# Same shape as phorum.t's "/admin.php". "/dashboard" is a bare segment with
# no trailing slash, so the byte after the needle must be checked. TEST 2 is
# the segment-termination oracle: "/dashboardZZ" continues with 'Z', neither
# a boundary byte nor EOF, and must CACHE. TEST 3 covers the two positive
# boundary arms ("/dashboard/extra" and "/dashboard.bak") that DO bypass.
# "/entry/", "/messages/", "/post/" are already slash-terminated, so they are
# plain byte-0 prefixes with no boundary ambiguity to test.
#
# THE VACUOUS URI TEST TRAP
# ------------------------------------------------------------------------
# uri_prefix() is byte-0 anchored, so a URI test served under a DIFFERENT
# location prefix (e.g. "/vanilla/dashboard") never reaches the rule at all
# and would pass with the row deleted. TEST 1 puts every URI arm at the ROOT
# path; TEST 9 is the explicit negative proving "/vanilla/dashboard" HITs
# precisely because the rule never fires off byte 0.
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

# Root-anchored prefix locations for every URI row. /vanilla/ carries the
# path-independent cookie cases and the byte-0 vacuity control. /gen/ is the
# isolation control -- a DIFFERENT preset.
our $Config = ct_config(
    { path => '/dashboard',  backend => 'vanilla' },
    { path => '/entry/',     backend => 'vanilla' },
    { path => '/messages/',  backend => 'vanilla' },
    { path => '/post/',      backend => 'vanilla' },
    { path => '/vanilla/',   backend => 'vanilla' },
    { path => '/gen/',       backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: every URI row bypasses at the root, with no cookie
# The full ct_vanilla_uris[] table, each on its own path so a shared key
# cannot mask a missing row. No arg leg, no predicate leg, no key-cookie leg.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /dashboard",     "GET /dashboard",
 "GET /entry/foo",     "GET /entry/foo",
 "GET /messages/foo",  "GET /messages/foo",
 "GET /post/foo",      "GET /post/foo"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200]



=== TEST 2: SEGMENT BOUNDARY -- /dashboardZZ must CACHE
# "/dashboard" is slash-less, so the boundary branch of
# ngx_http_cache_turbo_uri_prefix() is LIVE. The byte after the needle here
# is 'Z', not '/' or '.' and not end-of-URI, so this is a different path
# segment that merely shares the prefix and must cache. Served under the
# real /dashboard location so the HIT cannot pass for free on an implicit
# 404.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /dashboardZZ", "GET /dashboardZZ"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 3: the two positive boundary arms still bypass
# "/dashboard/extra" ('/' continuation) and "/dashboard.bak" ('.'
# continuation) are both inside the matched subtree per the boundary check.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /dashboard/extra", "GET /dashboard/extra",
 "GET /dashboard.bak",   "GET /dashboard.bak"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 4: the identity cookie Vanilla= bypasses under any path
# Cookie rules are path-independent -- asserted at /vanilla/, a location
# whose own URI carries no bypass rule of its own.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: Vanilla=abc.signed.payload
--- request eval
["GET /vanilla/discussion-a", "GET /vanilla/discussion-a"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 5: guest cookies Vanilla-tk / Vanilla-Vv stay CACHEABLE
# Ported from test_vanilla_guest_cookies_stay_cacheable(), guest direction.
# Both are issued to EVERY anonymous visitor from the same Garden.Cookie.Name
# prefix as the identity cookie; a bare-prefix rule would wrongly bypass
# every returning guest. The trailing '=' in "Vanilla=" is what excludes
# them.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: Vanilla-Vv=1; Vanilla-tk=1650000000.abcdef
--- request eval
["GET /vanilla/discussion-guest", "GET /vanilla/discussion-guest"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 6: identity cookie Vanilla= still bypasses alongside a guest cookie
# Ported from test_vanilla_guest_cookies_stay_cacheable(), authed direction.
# Same request also carries Vanilla-Vv, proving the identity cookie's
# presence -- not the guest cookies' absence -- is what triggers bypass.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: Vanilla-Vv=1; Vanilla=abc.signed.payload
--- request eval
["GET /vanilla/discussion-b", "GET /vanilla/discussion-b"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 7: suffix-under-any-prefix -- MyVanilla= also bypasses
# ngx_http_cache_turbo_cookie_has() matches the cookie NAME by SUFFIX
# (a substring anywhere in the Cookie header), so a prefixed cookie name
# ending in the same needle also matches. Pinned, not "fixed" -- this is the
# engine's documented behaviour, same shape as every other cookie_has() leg
# in this registry.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: MyVanilla=abc.signed.payload
--- request eval
["GET /vanilla/discussion-c", "GET /vanilla/discussion-c"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 8: bare valueless cookie Vanilla (no '=') must CACHE
# The needle is "Vanilla=" including the delimiter; a cookie named exactly
# "Vanilla" with no '=' at all never supplies that byte and must not match.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: Vanilla
--- request eval
["GET /vanilla/discussion-bare", "GET /vanilla/discussion-bare"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 9: THE VACUOUS URI TEST -- /vanilla/dashboard HITs, not byte-0
# uri_prefix() is byte-0 anchored, so a URI test served under a location
# whose path is NOT the root never reaches the rule. This proves a URI arm
# sent under /vanilla/ would pass for free even with the row deleted --
# exactly why every URI arm in TEST 1 is sent at the true root instead.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /vanilla/dashboard", "GET /vanilla/dashboard"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 10: the identity cookie under /gen/ (wordpress backend) still HITs
# Isolation control. wordpress has its own cookie list and the vanilla rows
# do not leak across backends.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: Vanilla=abc.signed.payload
--- request eval
["GET /gen/topic-iso", "GET /gen/topic-iso"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
