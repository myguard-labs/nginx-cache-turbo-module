# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Kirby preset (docs/kirby.md). Ported from test_kirby_preset() in
# ci/tools/test_runtime.py.
#
# THE BEST-SHAPED TRAFFIC OF ANY PRESET HERE
# ----------------------------------------------------------------------------
# A flat-file site is almost entirely public pages that are byte-identical for
# every logged-out visitor, which is the whole business case for a page cache.
#
# kirby_session is a STABLE literal (session.cookieName default) -- no hash, no
# APP_NAME, no admin-settable prefix -- AND Kirby creates a session only when
# something is actually stored in it, so a plain anonymous GET of a public page
# is issued NO cookie. Stable + not-guest-issued is the pair every rejected
# candidate failed: Grav's grav-site-<hash> is both guest-issued AND
# per-install; Craft's CraftSessionId is stable but handed to every visitor;
# Statamic's is APP_NAME-derived AND guest-issued.
#
# THE ONE CONDITION, AND IT FAILS SAFE
# ----------------------------------------------------------------------------
# Kirby's csrf() helper creates a session cookie ("When you use the csrf()
# helper, Kirby will create a session cookie" -- the privacy guide). So a
# template with a contact/search/comment form issues kirby_session TO GUESTS on
# that page, and those pages stop caching. That costs HITS on form pages; it
# never leaks, because the direction of the error is bypass-a-guest, not
# serve-a-member's-page. Precisely inverted from Flarum, whose no-remember-me
# logins carry only the guest-issued flarum_session -- which is why Flarum is
# rejected outright and this ships.
#
# "/panel" IS SLASH-LESS -- THE SEGMENT-TERMINATION BRANCH IS LIVE HERE
# ----------------------------------------------------------------------------
# Unlike ghost and wagtail, whose needles all carry their own trailing '/',
# ct_kirby_uris[] is { "/panel" } with no boundary of its own. So
# ngx_http_cache_turbo_uri_prefix() runs past its `pfx[l-1] == '/'`
# short-circuit and reaches the real trailing-byte check: the byte after the
# needle must be '/' or '.' or the URI must end there.
#
# That makes TEST 2 the classic segment-termination oracle rather than a byte-0
# anchor substitute. "/panels-and-doors" shares the "/panel" prefix but
# continues with 's', so it is a DIFFERENT path segment and must CACHE. Relax
# the boundary check to a bare prefix test and TEST 2 goes red. TEST 1 covers
# the other two arms of the same function: an exact match ("/panel", uri->len ==
# l) and a '/'-terminated continuation ("/panel/pages").
#
# /media IS DELIBERATELY ABSENT FROM ct_kirby_uris[]
# ----------------------------------------------------------------------------
# Kirby serves assets from /media/<hash>/ with no per-request permission view,
# so it is static content that SHOULD cache -- bypassing it would be a
# self-inflicted wound. TEST 7 pins that absence POSITIVELY, so a future edit
# that "helpfully" adds the prefix goes red instead of shipping a hit-rate loss.
#
# NO ARGS, NO KEY COOKIES, NO PREDICATES -- ct_kirby_args[] is { NULL }, and the
# kirby row in ngx_http_cache_turbo_presets[] carries NULL for both cookie_preds
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
# /panels-and-doors is its own ROOT location and is the segment-termination
# control: it must be genuinely routable and cacheable, or TEST 2 would pass on
# a 404 rather than on the boundary check.
#
# /kb/ is the public flat-file surface, carrying the cookie cases.
# /media/ proves the deliberate ABSENCE of a /media row in ct_kirby_uris[].
# /gen/ is the isolation control -- a DIFFERENT preset.
our $Config = ct_config(
    { path => '/panel',            backend => 'kirby' },
    { path => '/panels-and-doors', backend => 'kirby' },
    { path => '/kb/',              backend => 'kirby' },
    { path => '/media/',           backend => 'kirby' },
    { path => '/gen/',             backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: the /panel admin bypasses, exact and sub-path
# Two distinct arms of ngx_http_cache_turbo_uri_prefix(): "/panel" exactly
# (uri->len == l, the early `return 1`) and "/panel/pages" (a '/'-terminated
# continuation, the trailing-byte check). Fetched twice each because a bypass
# and a first-time MISS are indistinguishable from one fetch -- both lack
# X-Cache.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /panel", "GET /panel",
 "GET /panel/pages", "GET /panel/pages"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 2: SEGMENT BOUNDARY -- /panels-and-doors must CACHE
# This preset's engine-mutation oracle, and the reason kirby is worth porting
# separately from ghost and wagtail: "/panel" carries no trailing '/', so the
# boundary branch of ngx_http_cache_turbo_uri_prefix() is LIVE. The byte after
# the needle here is 's', not '/' or '.' and not end-of-URI, so
# /panels-and-doors is a different path segment and must cache.
#
# Relax the boundary check to a bare prefix test (make the function return 1 as
# soon as the prefix matches) and this test goes red. Sent under its own REAL
# location so the HIT assertion cannot pass for free on an implicit 404.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /panels-and-doors", "GET /panels-and-doors"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 3: the Kirby session cookie bypasses
# ct_kirby_cookies[] holds "kirby_session", the only cookie in the preset. A
# logged-in Panel user or frontend member is identified by nothing else. Sent on
# a public URL a guest can also fetch, so the bypass is attributable to the
# cookie and not to the path.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: kirby_session=abc123
--- request eval
["GET /kb/about", "GET /kb/about"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 4: a suffix-bearing cookie under ANY prefix still bypasses
# The bypass predicate matches the cookie NAME by suffix, so a proxy- or
# CDN-prefixed variant of the session cookie is still a login signal. If this
# were an exact-name match instead, a site behind a cookie-rewriting edge would
# serve Panel-user HTML from the shared bucket.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: __Secure-kirby_session=abc123
--- request eval
["GET /kb/post-b", "GET /kb/post-b"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 5: empty-valued and bare valueless session cookies still bypass
# A just-logged-out user is commonly served `kirby_session=` (an expiry-style
# clear) before the browser drops it, and a trimmed or malformed Cookie header
# may carry the bare name with no '=' at all. The predicate is NONEMPTY on the
# NAME, not on the value, so presence of the name is enough in both shapes.
# Pinned because an implementation that required a non-empty value would open a
# window where a logout-in-progress request is served from -- and populates --
# the shared bucket.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /kb/post-k", "GET /kb/post-k",
 "GET /kb/post-l", "GET /kb/post-l"]
--- more_headers eval
["Cookie: kirby_session=",
 "Cookie: kirby_session=",
 "Cookie: kirby_session",
 "Cookie: kirby_session"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 6: a matching cookie must not end the cookie scan
# The session cookie sits FIRST and an unrelated cookie follows. A scanner that
# returned early on its first match would still bypass here, so the
# load-bearing half is the reverse order below: an unrelated cookie first, the
# session cookie second. Both orders are sent so a regression in either
# direction is visible.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /kb/post-m", "GET /kb/post-m",
 "GET /kb/post-n", "GET /kb/post-n"]
--- more_headers eval
["Cookie: kirby_session=abc; _ga=GA1.2.3",
 "Cookie: kirby_session=abc; _ga=GA1.2.3",
 "Cookie: _ga=GA1.2.3; kirby_session=abc",
 "Cookie: _ga=GA1.2.3; kirby_session=abc"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 7: /media is deliberately NOT a preset URI and must keep caching
# Kirby serves assets from /media/<hash>/ with no per-request permission view,
# so it is static content that SHOULD cache. Bypassing it would be a
# self-inflicted wound -- a large share of a flat-file site's requests are
# exactly these. Pinned POSITIVELY so that adding "/media" to ct_kirby_uris[] --
# which would superficially look like a safety improvement -- goes red instead
# of shipping.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /media/pages/home/logo.svg", "GET /media/pages/home/logo.svg"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 8: an anonymous reader of the flat-file site CACHES
# The whole reason the preset ships, and the property that separates Kirby from
# every rejected candidate: Kirby issues an anonymous reader of a public page no
# cookie at all (a session is created only when something is stored in it). If
# this went red the preset would be caching nothing and every bypass test above
# would pass vacuously. The unrelated-cookie case is the negative half of TEST 3
# -- the cookie list is not "any cookie at all", or one analytics cookie would
# take the whole site off cache.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /kb/home", "GET /kb/home",
 "GET /kb/post-p", "GET /kb/post-p"]
--- more_headers eval
["", "",
 "Cookie: _ga=GA1.2.3.4",
 "Cookie: _ga=GA1.2.3.4"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]



=== TEST 9: an unrelated query arg still caches
# ct_kirby_args[] is { NULL } -- kirby has NO arg rows at all. A
# campaign-tagged URL must therefore cache like any other. Pinned because an
# engine that treated an empty arg table as "match everything" rather than
# "match nothing" would take the whole site off cache, and no other test in this
# file would catch it.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /kb/post-f?utm_source=twitter", "GET /kb/post-f?utm_source=twitter"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 10: the kirby rows do not leak into another backend's location
# /gen/ runs the wordpress preset. The kirby URI and cookie rules are opt-in per
# location; if the registry ORed every preset's rows together instead of
# selecting by bit, these would bypass here too. Both legs are exercised: a
# cookie row, and the URI row nested under /gen/.
#
# NOTE the cookie leg is a REAL cross-preset case, not a tautology: wordpress
# has its own cookie list and "kirby_session" is not on it.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /gen/post-a", "GET /gen/post-a",
 "GET /gen/panel/pages", "GET /gen/panel/pages"]
--- more_headers eval
["Cookie: kirby_session=abc123",
 "Cookie: kirby_session=abc123",
 "", ""]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]
