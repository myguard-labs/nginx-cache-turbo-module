# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Flarum preset (docs/flarum.md). Ported from two tests in
# ci/tools/test_runtime.py, both deleted by this port:
# test_flarum_session_cookie_is_not_a_login_signal() and
# test_flarum_admin_and_api_bypass() -- the /flarum/ fixture location that
# only those two tests used is also removed, and the shared "redmine /
# flarum / opencart" comment block above it is reworded to drop flarum
# (redmine and opencart still use it).
#
# THE COOKIE RULE MATCHES ONLY flarum_remember -- NEVER flarum_session
# ------------------------------------------------------------------------
# Verbatim from the ct_flarum_cookies[] header comment in src, because it is
# the whole point of this preset:
#
#   Http/Middleware/StartSession.php applies withSessionCookie()
#   unconditionally after $session->save(), on every response, before any
#   auth check, so `flarum_session` is issued to ANONYMOUS GUESTS. A rule
#   matching it would fire on ~100% of traffic and silently disable the
#   cache -- the guest-issued-cookie trap this registry's header comment
#   forbids. `flarum_remember` is written only by Http/Rememberer.php
#   (COOKIE_NAME = 'remember'), i.e. at login.
#
#   KNOWN GAP, documented rather than papered over: a user who logs in
#   WITHOUT "remember me" carries only `flarum_session`, whose guest and
#   member forms are distinguishable solely by the session id's
#   server-side mapping. nginx cannot tell them apart, so such a login is
#   invisible to the cookie tier. /api is in the URI tier partly to
#   contain that -- the SPA fetches its content through it -- but a
#   non-remembered login browsing plain discussion URLs is genuinely
#   unprotected by this preset alone. docs/flarum.md prescribes the
#   map-based rule for sites that need to close it.
#
# TEST 5 is the guest half (flarum_session alone must stay cacheable) and
# TEST 6 is the member half (flarum_remember must bypass, even alongside a
# flarum_session cookie) -- both directions matter: the guest half is what
# breaks if someone "fixes" the preset by adding the obvious session
# cookie, the member half is what breaks if the remember row is dropped.
#
# ct_flarum_args[] is { NULL } and the preset row carries NULL in both
# cookie_preds and key_cookies, so this file has no arg leg, no predicate
# leg, and no value-keying leg.
#
# THE URI LIST IS SLASH-LESS -- THE SEGMENT-TERMINATION BRANCH IS LIVE HERE
# ------------------------------------------------------------------------
# Every ct_flarum_uris[] row ("/admin", "/api", "/login", "/logout",
# "/global-logout", "/register", "/reset", "/confirm", "/settings",
# "/notifications") has no trailing slash, so the byte after the needle
# must be checked by ngx_http_cache_turbo_uri_prefix()'s boundary branch.
# TEST 2 is the segment-termination oracle: "/adminXtra" continues with
# 'X', neither a boundary byte nor EOF, and must CACHE. TEST 3 covers the
# two positive boundary arms ("/admin/extra" and "/admin.bak") that DO
# bypass.
#
# No row is a prefix of another: "/logout" and "/global-logout" differ at
# byte 0 ("l" vs "g"), so neither is a prefix of the other and the #222
# prefix-row rule does not apply here (checked pairwise against the full
# 10-row table).
#
# /admin and /api are also asserted cookie-less (TEST 4, the URI-tier
# member LEAK GUARD): a non-remembered login is invisible to the cookie
# tier, so these two rows are what stands between that gap and a real
# exposure -- ported from test_flarum_admin_and_api_bypass().
#
# THE VACUOUS URI TEST TRAP
# ------------------------------------------------------------------------
# uri_prefix() is byte-0 anchored, so a URI test served under a DIFFERENT
# location prefix (e.g. "/flarum/admin") never reaches the rule at all and
# would pass with the row deleted. TEST 1 puts every URI arm at the ROOT
# path; TEST 8 is the explicit negative proving "/flarum/admin" HITs
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

# Root-anchored prefix locations for every URI row. /flarum/ carries the
# path-independent cookie cases and the byte-0 vacuity control.
# /gen/ is the isolation control -- a DIFFERENT preset.
our $Config = ct_config(
    { path => '/admin',          backend => 'flarum' },
    { path => '/api',            backend => 'flarum' },
    { path => '/login',          backend => 'flarum' },
    { path => '/logout',         backend => 'flarum' },
    { path => '/global-logout',  backend => 'flarum' },
    { path => '/register',       backend => 'flarum' },
    { path => '/reset',          backend => 'flarum' },
    { path => '/confirm',        backend => 'flarum' },
    { path => '/settings',       backend => 'flarum' },
    { path => '/notifications',  backend => 'flarum' },
    { path => '/flarum/',        backend => 'flarum' },
    { path => '/gen/',           backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: every URI row bypasses at the root, with no cookie
# The full ct_flarum_uris[] table, each on its own path so a shared key
# cannot mask a missing row.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /admin",         "GET /admin",
 "GET /api",           "GET /api",
 "GET /login",         "GET /login",
 "GET /logout",        "GET /logout",
 "GET /global-logout", "GET /global-logout",
 "GET /register",      "GET /register",
 "GET /reset",         "GET /reset",
 "GET /confirm",       "GET /confirm",
 "GET /settings",      "GET /settings",
 "GET /notifications", "GET /notifications"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200,
 200, 200, 200, 200, 200]



=== TEST 2: SEGMENT BOUNDARY -- /adminXtra must CACHE
# "/admin" is slash-less, so the boundary branch of
# ngx_http_cache_turbo_uri_prefix() is LIVE. The byte after the needle here
# is 'X', not '/' or '.' and not end-of-URI, so this is a different path
# segment that merely shares the prefix and must cache. Served under the
# real /admin location so the HIT cannot pass for free on an implicit 404.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /adminXtra", "GET /adminXtra"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 3: the two positive boundary arms still bypass
# "/admin/extra" ('/' continuation) and "/admin.bak" ('.' continuation) are
# both inside the matched subtree per the boundary check.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /admin/extra", "GET /admin/extra",
 "GET /admin.bak",   "GET /admin.bak"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 4: URI-tier member LEAK GUARD -- /admin and /api bypass with NO cookie
# A non-remembered login carries only flarum_session, indistinguishable
# from a guest's on the wire, so the cookie tier alone cannot catch it.
# /admin and /api are what stands between that gap and a real exposure.
# Ported from test_flarum_admin_and_api_bypass().
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /admin", "GET /admin",
 "GET /api",   "GET /api"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 5: flarum_session ALONE -- the guest-issued probe -- does NOT bypass
# StartSession.php stamps flarum_session on every response, before any auth
# check, so it is issued to anonymous guests too. Matching it would fire on
# ~100% of traffic and silently disable the cache.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: flarum_session=eyJpdiI6Ilg5.guest.session.id
--- request eval
["GET /flarum/d/1-welcome", "GET /flarum/d/1-welcome"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 6: flarum_remember -- the real login signal -- MUST bypass
# Written only by Http/Rememberer.php (COOKIE_NAME = 'remember') at login.
# Present here alongside flarum_session (a real logged-in browser carries
# both), and the remember cookie's presence alone must force bypass.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: flarum_session=abc; flarum_remember=def.signed.token
--- request eval
["GET /flarum/d/2-topic", "GET /flarum/d/2-topic"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 7: an unrelated guest cookie does NOT bypass
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: flarum_tz=Europe%2FAmsterdam
--- request eval
["GET /flarum/d/topic-guest", "GET /flarum/d/topic-guest"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 8: THE VACUOUS URI TEST -- /flarum/admin HITs, not byte-0
# uri_prefix() is byte-0 anchored, so a URI test served under a location
# whose path is NOT the root never reaches the rule. This proves a URI arm
# sent under /flarum/ would pass for free even with the row deleted --
# exactly why every URI arm in TEST 1 is sent at the true root instead.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /flarum/admin", "GET /flarum/admin"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 9: the flarum_remember cookie under /gen/ (wordpress backend) still HITs
# Isolation control. wordpress has its own cookie list and the flarum rows
# do not leak across backends.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: flarum_remember=def.signed.token
--- request eval
["GET /gen/topic-iso", "GET /gen/topic-iso"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
