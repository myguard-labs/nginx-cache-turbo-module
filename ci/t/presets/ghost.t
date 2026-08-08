# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Ghost preset (docs/ghost.md). Ported from test_ghost_preset() in
# ci/tools/test_runtime.py.
#
# THE COOKIE BYPASS IS LOAD-BEARING, NOT DEFENCE-IN-DEPTH
# ----------------------------------------------------------------------------
# It is NOT true that a member sees the same HTML as a guest on a public post.
# Ghost's content gating (services/members/content-gating.js) does early-return
# on visibility === 'public' -- but `@member` is injected into the template
# context UNCONDITIONALLY whenever req.member exists
# (update-local-template-options.js), so a stock {{#if @member}} in the theme
# changes the markup of a FULLY PUBLIC post. Ghost itself agrees:
# frontend-caching.js sets `Cache-Control: private` for ANY member request
# without ever consulting visibility.
#
# ghost-members-ssr is the members session cookie (services/members/service.js),
# set ONLY on login -- an anonymous reader gets no cookie at all, which is the
# property that makes this preset worth shipping and which Moodle and the PHP
# shops lack. The substring also covers the ghost-members-ssr.sig signature
# cookie, so one entry does both (TEST 3 pins that, positively).
#
# THE ARG ROWS ARE THE SHARP EDGE -- COOKIELESS AUTHENTICATION
# ----------------------------------------------------------------------------
# Each arg row authenticates or unlocks WITHOUT A COOKIE, so the cookie rule
# above cannot catch any of them:
#   uuid + key  authMemberByUuid() (services/members/middleware.js)
#               authenticates a member purely from the QUERY STRING,
#               HMAC-verifying key against uuid. No cookie is involved at any
#               point.
#   token       the magic-link signin.
#   gift        a ?gift render serves UNLOCKED GATED CONTENT with no member
#               cookie present. Ghost's own cache middleware refuses to store
#               it for exactly this reason (isGiftRequest()).
# Store any of these and the paid/gated body is replayed to strangers. Do NOT
# drop them on the theory that the Cache-Control floor covers you: an operator
# running `cache_turbo_cache_control ignore` (which the README recommends for
# some origins) has switched that floor off, and these tests run with the
# ordinary floor in place precisely so the ARG RULE, not the floor, is what is
# being measured -- the origin here returns `public, max-age=30`.
#
# EVERY GHOST URI NEEDLE ENDS IN '/' -- THE SEGMENT-TERMINATION BRANCH IS
# UNREACHABLE FOR THIS PRESET, AND THAT IS WHY TEST 2 LOOKS DIFFERENT
# ----------------------------------------------------------------------------
# ct_ghost_uris[] is { "/ghost/", "/members/", "/p/", "/r/" } -- all four carry
# their own trailing slash. ngx_http_cache_turbo_uri_prefix() short-circuits at
# `if (pfx[l - 1] == '/') return 1;`, so the trailing-boundary-byte check
# ('/', '.', EOF) that xenforo, magento and shopware6 exercise never runs here.
# There is therefore NO "/ghostX must not bypass" case to write: "/ghostX" does
# not even match "/ghost/" bytewise.
#
# The property that IS load-bearing for ghost is the BYTE-0 ANCHOR: the needle
# must match at position 0, not anywhere in the path. TEST 2 sends
# "/blog/ghost/x" -- which contains "/ghost/" as a substring but not at byte 0
# -- and requires it to HIT. Delete the anchor (make the compare a substring
# search) and TEST 2 goes red. That is this preset's engine-mutation oracle,
# and it is a REAL location so the assertion cannot pass for free on an
# implicit 404 (which also carries no X-Cache).
#
# /p/ AND /r/ ARE ONE AND TWO BYTES OF PATH
# ----------------------------------------------------------------------------
# /p/ is unpublished post previews (must never be cached) and /r/ is the
# link-redirect tracker. They are the shortest needles in the whole preset
# table; TEST 1 exercises both, which also pins that a short needle is not
# accidentally treated as a match-everything.
#
# NO KEY COOKIES, NO PREDICATES -- the ghost row in
# ngx_http_cache_turbo_presets[] carries NULL for both cookie_preds and
# key_cookies, so this file has no value-keying leg and no predicate leg. Only
# the URI, cookie-bypass and arg legs apply.
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

# The preset's URI rules are prefixes anchored at byte 0, so each one gets its
# own ROOT location -- without a real location nginx's implicit 404 also
# carries no X-Cache and a "must bypass" assertion would pass for free.
#
# /blog/ is the public reader surface: it carries the cookie cases, the arg
# cases and the byte-0 anchor negative, all of which are path-independent. Its
# key is $uri (ct_location's default), NOT $uri$is_args$args -- load-bearing:
# an arg-rule test asserts a BYPASS, and if the query string were in the cache
# key the request would simply be a MISS on a fresh entry and TEST 5 would pass
# with ct_ghost_args[] deleted entirely.
#
# /gen/ is the isolation control -- a DIFFERENT preset, proving the ghost rows
# are opt-in and do not leak into another backend's location.
our $Config = ct_config(
    { path => '/ghost/',   backend => 'ghost' },
    { path => '/members/', backend => 'ghost' },
    { path => '/p/',       backend => 'ghost' },
    { path => '/r/',       backend => 'ghost' },
    { path => '/blog/',    backend => 'ghost' },
    { path => '/gen/',     backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: every ghost URI rule bypasses
# /ghost/ is the admin SPA and Admin API; /members/ the members endpoints;
# /p/ unpublished post previews; /r/ the link-redirect tracker. Fetched twice
# each because a bypass and a first-time MISS are indistinguishable from one
# fetch -- both lack X-Cache.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /ghost/api/admin/site", "GET /ghost/api/admin/site",
 "GET /members/api/member", "GET /members/api/member",
 "GET /p/draft-abc", "GET /p/draft-abc",
 "GET /r/click-xyz", "GET /r/click-xyz"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200]



=== TEST 2: BYTE-0 ANCHOR -- "/ghost/" nested inside a path must NOT bypass
# This preset's engine-mutation oracle. Every ghost needle ends in '/', so
# ngx_http_cache_turbo_uri_prefix() returns at its `pfx[l-1] == '/'`
# short-circuit and the segment-termination branch never runs -- there is no
# "/ghostX" case to write. What IS load-bearing is that the compare is anchored
# at position 0. "/blog/ghost/x" contains "/ghost/" verbatim but not at byte 0,
# so it must cache. Turn the anchored ngx_strncmp into a substring search and
# this test goes red.
#
# Sent under the REAL /blog/ location, not an unrouted path: an implicit 404
# carries no X-Cache either, and the HIT assertion on the second fetch is what
# makes this non-vacuous.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /blog/ghost/x", "GET /blog/ghost/x"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 3: the members session cookie bypasses, .sig variant included
# ct_ghost_cookies[] holds "ghost-members-ssr"; the bypass predicate matches a
# cookie name by SUFFIX, and "ghost-members-ssr.sig" is not a suffix of it --
# the coverage comes from the OTHER direction, the preset entry being a prefix
# of the real cookie name in the header scan. Both variants are pinned here
# because the module source claims one entry does both; a change that broke the
# .sig half would otherwise ship silently.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /blog/post-a", "GET /blog/post-a",
 "GET /blog/post-a", "GET /blog/post-a",
 "GET /blog/post-a", "GET /blog/post-a"]
--- more_headers eval
["Cookie: ghost-members-ssr=abc123",
 "Cookie: ghost-members-ssr=abc123",
 "Cookie: ghost-members-ssr.sig=deadbeef",
 "Cookie: ghost-members-ssr.sig=deadbeef",
 "Cookie: ghost-admin-api-session=cafe",
 "Cookie: ghost-admin-api-session=cafe"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 4: a suffix-bearing cookie under ANY prefix still bypasses
# The bypass predicate matches the cookie NAME by suffix, so a proxy- or
# CDN-prefixed variant of the members cookie is still a member signal. If this
# were an exact-name match instead, a site behind a cookie-rewriting edge would
# serve member HTML from the shared bucket.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: __Secure-ghost-members-ssr=abc123
--- request eval
["GET /blog/post-b", "GET /blog/post-b"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 5: COOKIELESS MEMBER AUTH -- every arg row bypasses
# The sharp edge. ?uuid=&key= authenticates a member with no cookie at all
# (authMemberByUuid, HMAC-verifying key against uuid); ?token= is the
# magic-link signin; ?gift= serves UNLOCKED GATED content to a caller with no
# member cookie. If any of these fails to bypass, a member-authenticated or
# paid body is stored under the anonymous key and replayed to strangers.
#
# The /blog/ cache key is $uri only, so the query string does not split the
# entry by itself -- a MISS here can only come from the ARG RULE.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /blog/post-c?uuid=abc-123&key=deadbeef", "GET /blog/post-c?uuid=abc-123&key=deadbeef",
 "GET /blog/post-c?token=magiclink123", "GET /blog/post-c?token=magiclink123",
 "GET /blog/post-c?gift=abc123", "GET /blog/post-c?gift=abc123"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 5b: ?key= alone bypasses -- the rows are independent, not a pair
# uuid and key are separate rows in ct_ghost_args[]. Ghost's own
# authMemberByUuid needs both, but the preset must not require the pair: a rule
# that only fired on uuid AND key together would miss a request carrying key
# with the uuid supplied by some other means, and the module has no business
# modelling Ghost's argument arity.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /blog/post-d?key=deadbeef", "GET /blog/post-d?key=deadbeef",
 "GET /blog/post-e?uuid=abc-123", "GET /blog/post-e?uuid=abc-123"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 6: an unrelated query arg still caches -- the negative half of TEST 5
# If the arg rule matched on the PRESENCE of any query string, every
# campaign-tagged blog URL would bypass and the cache would be off site-wide.
# Note the cache key is $uri, so a bypass here would be visible as a missing
# X-Cache and could not be mistaken for key separation.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /blog/post-f?utm_source=twitter", "GET /blog/post-f?utm_source=twitter"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 7: an arg row is matched as a whole NAME, not as a substring
# "uuidx" and "gifting" both contain a ghost arg name as a prefix. Matching
# those would bypass on arbitrary third-party parameters. The negative is worth
# pinning separately from TEST 6 because a substring-matching arg scanner would
# still pass TEST 6 (utm_source contains no ghost arg name).
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /blog/post-g?uuidx=1", "GET /blog/post-g?uuidx=1",
 "GET /blog/post-h?gifting=1", "GET /blog/post-h?gifting=1"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]



=== TEST 8: an arg row is matched wherever it sits in the query string
# The scanner must not be anchored to the first parameter. A ?gift= arriving
# after two unrelated parameters unlocks gated content just the same.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /blog/post-i?utm_source=x&ref=y&gift=abc123",
 "GET /blog/post-i?utm_source=x&ref=y&gift=abc123"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 9: a bare valueless arg row still bypasses
# `?gift` with no `=` is presence, and presence is the signal -- ct_ghost_args[]
# rows are bare NAMEs (no '='), which the scanner treats as
# "the argument is present, whatever its value".
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /blog/post-j?gift", "GET /blog/post-j?gift"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 10: an empty-valued members cookie still bypasses
# A logged-out member is commonly served `ghost-members-ssr=` (an expiry-style
# clear) before the browser drops it. The predicate is NONEMPTY on the NAME,
# not on the value, so presence of the name is enough. Pinned because an
# implementation that required a non-empty value would open a window where a
# just-logged-out request is served from -- and populates -- the shared bucket.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: ghost-members-ssr=
--- request eval
["GET /blog/post-k", "GET /blog/post-k"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 11: a bare valueless members cookie still bypasses
# No '=' at all. A malformed or trimmed Cookie header must not be a way to slip
# a member request into the anonymous bucket.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: ghost-members-ssr
--- request eval
["GET /blog/post-l", "GET /blog/post-l"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 12: a matching cookie must not end the cookie scan
# The members cookie sits FIRST and an unrelated cookie follows. A scanner that
# returned early on its first match would still bypass here, so the load-bearing
# half is the reverse order below: an unrelated cookie first, the members cookie
# second. Both orders are sent so a regression in either direction is visible.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /blog/post-m", "GET /blog/post-m",
 "GET /blog/post-n", "GET /blog/post-n"]
--- more_headers eval
["Cookie: ghost-members-ssr=abc; _ga=GA1.2.3",
 "Cookie: ghost-members-ssr=abc; _ga=GA1.2.3",
 "Cookie: _ga=GA1.2.3; ghost-members-ssr=abc",
 "Cookie: _ga=GA1.2.3; ghost-members-ssr=abc"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 13: an anonymous blog reader CACHES
# The whole reason the preset ships. Ghost issues an anonymous reader no cookie
# at all, so the public blog is a genuinely shared surface. If this went red the
# preset would be caching nothing and every test above would pass vacuously.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /blog/post-o", "GET /blog/post-o"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 14: an unrelated cookie does not bypass
# The negative half of TEST 3. If the cookie list were treated as
# "any cookie at all", an analytics cookie would take the whole blog off cache.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: _ga=GA1.2.3.4
--- request eval
["GET /blog/post-p", "GET /blog/post-p"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 15: the ghost rows do not leak into another backend's location
# /gen/ runs the wordpress preset. The ghost URI, cookie and arg rules are
# opt-in per location; if the registry ORed every preset's rows together
# instead of selecting by bit, these would bypass here too. All three legs are
# exercised: an arg row, a cookie row, and a URI row nested under /gen/.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /gen/post-a?gift=abc123", "GET /gen/post-a?gift=abc123",
 "GET /gen/post-b", "GET /gen/post-b"]
--- more_headers eval
["", "",
 "Cookie: ghost-members-ssr=abc123",
 "Cookie: ghost-members-ssr=abc123"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]
