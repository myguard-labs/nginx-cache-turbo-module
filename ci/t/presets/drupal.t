# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Drupal preset (docs/drupal.md). Ported from test_drupal_preset() in
# ci/tools/test_runtime.py.
#
# THE SESS COOKIE RULE IS A LEAK FIX, NOT A NICETY
# -------------------------------------------------
# THIS USED TO SHIP NO COOKIE RULE. That was a LEAK, and the reasoning behind it
# was factually wrong. The old comment claimed "anonymous readers get no session
# cookie at all", so the Cache-Control floor alone was enough. Drupal does not
# work that way: it opens a session for an ANONYMOUS user as soon as anything
# writes to $_SESSION, and core's own NoSessionOpen docblock names the everyday
# cases -- a status message queued by a form submission, and cart contents. Once
# that happens the visitor holds SESS<hash>, and a logged-IN user holds the same
# cookie shape. With no cookie rule, an authenticated response could be stored
# and served to a stranger the moment the Cache-Control floor was not there to
# catch it (`cache_turbo_cache_control ignore` removes it, and the README
# recommends that mode for some origins). Correctness cannot rest on that floor.
#
# THE KNOWN COST, accepted deliberately: "SESS" is a substring of PHPSESSID and
# JSESSIONID, so on a box that co-hosts another PHP or Java app under the same
# server block, this rule also bypasses on THAT app's session cookie. That is a
# hit-rate loss, never a leak -- and a hit-rate loss on a co-hosted app is not a
# reason to keep leaking on the Drupal one. TEST 6 pins this trade-off so it
# cannot regress silently.
#
# The hash is per-install (derived from the hostname -- Core/Session/
# SessionConfiguration.php), so "SESS" is the ONLY shippable literal; matching
# the full name is impossible.
#
# WHY THE COOKIE MATCH IS A RAW SUBSTRING, NOT NAME-SUFFIX OR EXACT
# -------------------------------------------------------------------
# Unlike the predicate/key-cookie tiers used by other presets, this preset's
# cookie rule (ct_drupal_cookies) is checked by
# ngx_http_cache_turbo_cookie_has(), which runs a bounded substring scan over
# the RAW Cookie header bytes -- it does not parse cookie names at all. "SESS"
# bypasses
# if it appears ANYWHERE in the header, cookie name or value, which is what
# makes both SESS<hash> and SSESS<hash> match with one literal and is also why
# PHPSESSID (a *substring* match, not a suffix or prefix) collides.
#
# NOT NO_CACHE, NOT a preds/key_cookies preset: the drupal table row is
# { ct_drupal_cookies, ct_drupal_uris, ct_drupal_args, NULL, NULL } -- args is
# an empty ({NULL}) list and there are no predicate or key-cookie legs, so this
# file has no arg-rule tests, no predicate tests and no key-cookie tests.
#
# HEADER-AUTHENTICATED SURFACES (/jsonapi, /oauth)
# --------------------------------------------------
# /jsonapi and /oauth are the HEADER-AUTHENTICATED surfaces. The cookie tier
# cannot see them at all: an API client sends `Authorization: Bearer ...` and no
# SESS cookie, so the cookie rule above is structurally blind to it. /oauth/
# userinfo is the one that makes this a leak rather than a nicety: it is a GET,
# authenticated purely by the bearer token, and it returns the token holder's
# profile. Core REST (?_format=json on an arbitrary entity path) is NOT
# coverable by a prefix and is not tested here -- see docs/drupal.md.
# (Cross-preset coverage of /jsonapi and /oauth as header-auth REST surfaces
# alongside magento/wordpress lives in test_header_auth_rest_surfaces() in
# ci/tools/test_runtime.py and is intentionally NOT ported here or deleted --
# it is a vehicle test, not a drupal test.)
#
# See ci/t/presets/xenforo.t for why every bypass case is fetched TWICE and why
# these are `--- request eval` arrays rather than `--- pipelined_requests`.
# See ci/t/presets/mybb.t for the exact-vs-suffix key/predicate asymmetry
# pinned elsewhere in this registry (not exercised by this preset).

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

# The preset's URI rules are prefixes anchored at byte 0, so /user, /admin,
# /node/add, /system/, /core/install.php, /jsonapi and /oauth must be ROOT
# locations. /dr/ carries the cookie cases, which are path-independent.
# /users-directory-info is the segment-termination lookalike for TEST 6 --
# nginx's longest-prefix-match picks this location over /user for that exact
# path, so the request actually reaches a cache-enabled drupal backend instead
# of 404ing. /gen/ is the isolation control -- a DIFFERENT preset, proving the
# drupal rows are opt-in and do not leak into another backend's location.
our $Config = ct_config(
    { path => '/user',              backend => 'drupal'    },
    { path => '/admin',             backend => 'drupal'    },
    { path => '/node/add',          backend => 'drupal'    },
    { path => '/system/',           backend => 'drupal'    },
    { path => '/core/install.php',  backend => 'drupal'    },
    { path => '/jsonapi',           backend => 'drupal'    },
    { path => '/oauth',             backend => 'drupal'    },
    { path => '/dr/',               backend => 'drupal'    },
    { path => '/users-directory-info', backend => 'drupal' },
    { path => '/gen/',              backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: /user bypasses on the URI rule
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /user", "GET /user"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 2: /user/1/edit bypasses -- a slash-less needle matches at a '/' boundary
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /user/1/edit", "GET /user/1/edit"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 3: /admin/config bypasses, and /system/ (a self-terminated needle) bypasses too
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /admin/config", "GET /admin/config",
 "GET /system/cron",  "GET /system/cron"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 4: /node/add and /core/install.php bypass -- a '.' boundary counts too
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /node/add",           "GET /node/add",
 "GET /core/install.php",   "GET /core/install.php"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 5: /jsonapi and /oauth bypass -- the header-authenticated surfaces
# The cookie tier cannot see these at all (bearer-token auth, no SESS cookie);
# only the URI rule protects them. /oauth/userinfo is the leak that justifies
# the prefix -- see the file header.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /jsonapi/node/article", "GET /jsonapi/node/article",
 "GET /oauth/userinfo",       "GET /oauth/userinfo",
 "GET /oauth/debug",          "GET /oauth/debug"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 6: a URI that merely shares a segment prefix does NOT bypass -- segment termination
# /users-directory-info begins with the needle /user at byte 0 and continues
# with 's', which is neither '/' nor '.' nor end-of-URI -- so the segment-
# terminator check in ngx_http_cache_turbo_uri_prefix must reject this as a
# match for the /user rule. If that check were deleted (a plain raw prefix
# match that accepts any following byte), this request would incorrectly
# bypass the cache instead of being served from it, so caching (a HIT on the
# second request) is what proves the terminator logic is doing its job.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /users-directory-info", "GET /users-directory-info"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 7: SESS<hash> and SSESS<hash> (the TLS variant) both bypass -- THE LEAK GUARD
# The cookie is opened for an ANONYMOUS visitor too (core's NoSessionOpen
# cases), so its mere presence -- not a value predicate -- must bypass. Without
# this rule an authenticated response could be stored and served to a stranger.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers eval
["Cookie: SESS1a2b3c4d5e6f=authsession", "Cookie: SESS1a2b3c4d5e6f=authsession",
 "Cookie: SSESSdeadbeefcafe=authsession", "Cookie: SSESSdeadbeefcafe=authsession"]
--- request eval
["GET /dr/node-a", "GET /dr/node-a",
 "GET /dr/node-a", "GET /dr/node-a"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 8: PHPSESSID collides with the SESS substring and bypasses -- THE ACCEPTED COST
# "SESS" is a raw substring match over the whole Cookie header, not a
# per-cookie-name match, so a co-hosted PHP app's PHPSESSID also bypasses here.
# That is a hit-rate loss on the other app, never a leak, and is accepted
# deliberately -- see the file header. Pinned explicitly so it cannot regress
# silently into "PHPSESSID caches" (which would mean the SESS rule stopped
# matching a real Drupal SESS<hash> too).
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: PHPSESSID=abc123
--- request eval
["GET /dr/node-b", "GET /dr/node-b"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 9: a cookieless anonymous reader still caches
# The preset is not a blanket bypass -- that is the whole point of it existing
# rather than just disabling the cache for the location.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /dr/node-c", "GET /dr/node-c"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 10: a leading logged-out SESS pair must not mask a later logged-in one
# The bounded scan over the raw header is a substring search, so
# a SECOND occurrence of "SESS" later in the header must still be found -- the
# scan must not stop at the first cookie in the pair. Two Set-Cookie-shaped
# entries in one header, only the second carrying a value; the whole header
# must still bypass.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: other=x; SESSlogged=authsession
--- request eval
["GET /dr/node-d", "GET /dr/node-d"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 11: the drupal rows do not leak into another backend's location
# /gen/ runs the wordpress preset. /user is a drupal URI rule, not a wordpress
# one, so the generic location must cache it -- proving the rule is preset-
# scoped, not global.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /gen/user", "GET /gen/user"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 12: a drupal SESS cookie does not bypass under the wordpress preset
# The cookie half of TEST 11. SESS<hash> is not a wordpress signal, so the
# generic location must cache it -- proving the cookie rule is preset-scoped.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: SESS1a2b3c4d5e6f=authsession
--- request eval
["GET /gen/node", "GET /gen/node"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
