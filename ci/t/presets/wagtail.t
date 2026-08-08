# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Wagtail preset (docs/wagtail.md). Ported from test_wagtail_preset() in
# ci/tools/test_runtime.py.
#
# THE FIRST PRESET WHOSE AUTH COOKIE BELONGS TO THE FRAMEWORK, NOT THE APP
# ----------------------------------------------------------------------------
# Wagtail ships no cookie of its own -- it rides Django's `sessionid`. That is
# only shippable because of a specific Django property: SessionMiddleware saves
# the session cookie ONLY when the session is non-empty AND modified, so a
# logged-out reader of a public page is issued no cookie at all. Contrast
# Laravel, whose StartSession has no such check and cookies every guest -- which
# is why there is no statamic/october/laravel preset and never will be
# (docs/frameworks.md).
#
# THE CONDITION IS THE APP'S TO BREAK. `sessionid` stops being a logged-in
# signal the moment the site writes to the session for anonymous visitors: an
# anonymous cart, a large guest flash message (contrib.messages overflows cookie
# storage and falls back to the SESSION), or CSRF_USE_SESSIONS=True. Each turns
# the bypass into a 100% bypass -- hit rate 0, no error, nothing in the log.
# It FAILS SAFE (lost hits, never a leak), which is the only reason it ships.
#
# THE TWO ASSERTIONS THAT MATTER PULL IN OPPOSITE DIRECTIONS
# ----------------------------------------------------------------------------
#   sessionid  MUST bypass      (TEST 3) or a logged-in editor is served from,
#                               and stored into, the shared anonymous bucket.
#   csrftoken  MUST NOT bypass  (TEST 8) or the hit rate goes to zero.
# Django hands csrftoken to ANY anonymous visitor who renders a form -- a search
# box in the header is enough. Treating it as a login signal is the classic way
# to build a cache that caches nothing, and it does so SILENTLY: the preset
# still "looks" correct, it just stops caching. TEST 8 fails loudly instead.
# Same class as WooCommerce's guest cookies.
#
# EVERY WAGTAIL URI NEEDLE ENDS IN '/' -- THE SEGMENT-TERMINATION BRANCH IS
# UNREACHABLE FOR THIS PRESET, AND THAT IS WHY TEST 2 LOOKS DIFFERENT
# ----------------------------------------------------------------------------
# ct_wagtail_uris[] is { "/admin/", "/django-admin/", "/documents/" } -- all
# three carry their own trailing slash. ngx_http_cache_turbo_uri_prefix()
# short-circuits at `if (pfx[l - 1] == '/') return 1;`, so the trailing
# boundary-byte check ('/', '.', EOF) that xenforo, magento and shopware6
# exercise never runs here. There is NO "/adminX must not bypass" case to write:
# "/adminX" does not even match "/admin/" bytewise.
#
# The property that IS load-bearing is the BYTE-0 ANCHOR: the needle must match
# at position 0, not anywhere in the path. TEST 2 sends "/wt/admin/x" -- which
# contains "/admin/" verbatim but not at byte 0 -- and requires it to HIT.
# Delete the anchor (make the compare a substring search) and TEST 2 goes red.
# That is this preset's engine-mutation oracle, and it is sent under a REAL
# location so the assertion cannot pass for free on an implicit 404 (which also
# carries no X-Cache).
#
# /documents/ IS LOAD-BEARING, NOT DECORATION
# ----------------------------------------------------------------------------
# WAGTAILDOCS_SERVE_METHOD defaults to serve_view under FileSystemStorage: a
# Django view that enforces per-collection PRIVACY checks. A private document
# fetched by an authorised user must never be stored and replayed to a stranger.
# The prefix is bypassed rather than trusting a no-store header we have not
# verified. /admin/ and /django-admin/ are relocatable (the docs suggest /cms/
# when wagtailadmin clashes with Django admin) -- an install that moves them
# loses the URI shortcut but stays CORRECT, because `sessionid` is the real
# guard. Cookie guards, URI optimises; that ordering is deliberate.
#
# /search/ IS DELIBERATELY ABSENT FROM ct_wagtail_uris[]
# ----------------------------------------------------------------------------
# It is dynamic but ANONYMOUS-IDENTICAL -- every logged-out visitor searching
# "foo" gets the same page -- so it is shared, hot, and exactly what a cache is
# for. Bypassing it would be a pure hit-rate loss with no safety gain. Same
# reasoning that keeps a blanket `action=` out of mediawiki. TEST 9 pins the
# absence positively, so a future edit that "helpfully" adds it goes red.
#
# NO ARGS, NO KEY COOKIES, NO PREDICATES -- ct_wagtail_args[] is { NULL }, and
# the wagtail row in ngx_http_cache_turbo_presets[] carries NULL for both
# cookie_preds and key_cookies. This file therefore has no arg leg, no predicate
# leg and no value-keying leg. Only the URI and cookie-bypass legs apply.
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
# own ROOT location -- without a real location nginx's implicit 404 also carries
# no X-Cache and a "must bypass" assertion would pass for free.
#
# /wt/ is the public site surface: it carries the cookie cases and the byte-0
# anchor negative, both of which are path-independent.
#
# /search/ is a REAL cache-enabled location under the wagtail backend, proving
# the deliberate ABSENCE of a /search/ row in ct_wagtail_uris[].
#
# /gen/ is the isolation control -- a DIFFERENT preset, proving the wagtail rows
# are opt-in and do not leak into another backend's location.
our $Config = ct_config(
    { path => '/admin/',        backend => 'wagtail' },
    { path => '/django-admin/', backend => 'wagtail' },
    { path => '/documents/',    backend => 'wagtail' },
    { path => '/wt/',           backend => 'wagtail' },
    { path => '/search/',       backend => 'wagtail' },
    { path => '/gen/',          backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: every wagtail URI rule bypasses
# /admin/ is wagtailadmin_urls; /django-admin/ is admin.site.urls (both from
# Wagtail's own project template); /documents/ is the permission-checked
# serve_view surface. Fetched twice each because a bypass and a first-time MISS
# are indistinguishable from one fetch -- both lack X-Cache.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /admin/pages/", "GET /admin/pages/",
 "GET /django-admin/auth/user/", "GET /django-admin/auth/user/",
 "GET /documents/3/private-contract.pdf", "GET /documents/3/private-contract.pdf"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 2: BYTE-0 ANCHOR -- "/admin/" nested inside a path must NOT bypass
# This preset's engine-mutation oracle. Every wagtail needle ends in '/', so
# ngx_http_cache_turbo_uri_prefix() returns at its `pfx[l-1] == '/'`
# short-circuit and the segment-termination branch never runs -- there is no
# "/adminX" case to write. What IS load-bearing is that the compare is anchored
# at position 0. "/wt/admin/x" contains "/admin/" verbatim but not at byte 0, so
# it must cache. Turn the anchored ngx_strncmp into a substring search and this
# test goes red.
#
# Sent under the REAL /wt/ location, not an unrouted path: an implicit 404
# carries no X-Cache either, and the HIT assertion on the second fetch is what
# makes this non-vacuous.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wt/admin/x", "GET /wt/admin/x",
 "GET /wt/documents/y", "GET /wt/documents/y"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]



=== TEST 3: the Django session cookie bypasses
# ct_wagtail_cookies[] holds "sessionid", the ONLY cookie in the preset. A
# logged-in Wagtail editor is identified by nothing else. Both the bare cookie
# and the realistic pairing with csrftoken are sent: an editor's browser carries
# both, and the sessionid half must still win.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wt/about", "GET /wt/about",
 "GET /wt/about", "GET /wt/about"]
--- more_headers eval
["Cookie: sessionid=abc123",
 "Cookie: sessionid=abc123",
 "Cookie: sessionid=abc123; csrftoken=xyz",
 "Cookie: sessionid=abc123; csrftoken=xyz"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 4: a suffix-bearing cookie under ANY prefix still bypasses
# The bypass predicate matches the cookie NAME by suffix, so a proxy- or
# CDN-prefixed variant of the session cookie is still a login signal. Django
# itself ships SESSION_COOKIE_NAME as a setting and the __Secure- prefix is a
# standard hardening move, so this is not a hypothetical shape. If this were an
# exact-name match instead, a site behind a cookie-rewriting edge -- or one that
# merely set SESSION_COOKIE_NAME = "my_sessionid" -- would serve editor HTML
# from the shared bucket.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: __Secure-sessionid=abc123
--- request eval
["GET /wt/post-b", "GET /wt/post-b"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 5: an empty-valued session cookie still bypasses
# A just-logged-out editor is commonly served `sessionid=` (an expiry-style
# clear) before the browser drops it. The predicate is NONEMPTY on the NAME, not
# on the value, so presence of the name is enough. Pinned because an
# implementation that required a non-empty value would open a window where a
# logout-in-progress request is served from -- and populates -- the shared
# bucket.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: sessionid=
--- request eval
["GET /wt/post-k", "GET /wt/post-k"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 6: a bare valueless session cookie still bypasses
# No '=' at all. A malformed or trimmed Cookie header must not be a way to slip
# an editor request into the anonymous bucket.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: sessionid
--- request eval
["GET /wt/post-l", "GET /wt/post-l"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 7: a matching cookie must not end the cookie scan
# The session cookie sits FIRST and an unrelated cookie follows. A scanner that
# returned early on its first match would still bypass here, so the
# load-bearing half is the reverse order below: an unrelated cookie first, the
# session cookie second. Both orders are sent so a regression in either
# direction is visible.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wt/post-m", "GET /wt/post-m",
 "GET /wt/post-n", "GET /wt/post-n"]
--- more_headers eval
["Cookie: sessionid=abc; _ga=GA1.2.3",
 "Cookie: sessionid=abc; _ga=GA1.2.3",
 "Cookie: _ga=GA1.2.3; sessionid=abc",
 "Cookie: _ga=GA1.2.3; sessionid=abc"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 8: THE INVERTED ONE -- csrftoken must NOT bypass
# Django hands csrftoken to any ANONYMOUS visitor who renders a form; a search
# box in the site header is enough. If a future edit adds it to
# ct_wagtail_cookies[] the preset still looks correct -- it just silently stops
# caching, hit rate zero, no error and nothing in the log. This is the single
# most valuable assertion in the file precisely because the failure mode is
# invisible. The unrelated _ga case is the same property from the other
# direction: the cookie list is not "any cookie at all".
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wt/pricing", "GET /wt/pricing",
 "GET /wt/post-p", "GET /wt/post-p"]
--- more_headers eval
["Cookie: csrftoken=xyz",
 "Cookie: csrftoken=xyz",
 "Cookie: _ga=GA1.2.3.4",
 "Cookie: _ga=GA1.2.3.4"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]



=== TEST 9: /search/ is deliberately NOT a preset URI and must keep caching
# Dynamic but ANONYMOUS-IDENTICAL: every logged-out visitor searching "nginx"
# gets the same page, so it is shared, hot and exactly what a cache is for.
# Bypassing it would be a pure hit-rate loss with no safety gain. Pinned
# POSITIVELY so that adding "/search/" to ct_wagtail_uris[] -- which would look
# like a safety improvement -- goes red instead of shipping.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /search/?q=nginx", "GET /search/?q=nginx"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 10: an anonymous reader of the public site CACHES
# The whole reason the preset ships. Django issues an anonymous reader of a
# public page no cookie at all (SessionMiddleware saves only a non-empty AND
# modified session), so the public site is a genuinely shared surface. If this
# went red the preset would be caching nothing and every bypass test above would
# pass vacuously.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wt/home", "GET /wt/home"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 11: an unrelated query arg still caches
# ct_wagtail_args[] is { NULL } -- wagtail has NO arg rows at all. A
# campaign-tagged URL must therefore cache like any other. Pinned because an
# engine that treated an empty arg table as "match everything" rather than
# "match nothing" would take the whole site off cache, and no other test in this
# file would catch it.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wt/post-f?utm_source=twitter", "GET /wt/post-f?utm_source=twitter"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 12: the wagtail rows do not leak into another backend's location
# /gen/ runs the wordpress preset. The wagtail URI and cookie rules are opt-in
# per location; if the registry ORed every preset's rows together instead of
# selecting by bit, these would bypass here too. Both legs are exercised: a
# cookie row, and a URI row nested under /gen/.
#
# NOTE the cookie leg is a REAL cross-preset case, not a tautology: wordpress
# has its own cookie list and "sessionid" is not on it.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /gen/post-a", "GET /gen/post-a",
 "GET /gen/admin/pages/", "GET /gen/admin/pages/"]
--- more_headers eval
["Cookie: sessionid=abc123",
 "Cookie: sessionid=abc123",
 "", ""]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]
