# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Plone preset (docs/plone.md). Ported from ci/tools/test_runtime.py cases:
# test_plone_cookies(), test_plone_uris(), and the plone half of
# test_plone_discourse_bypass_caching() -- deleted by this port.
#
# THE COOKIE RULE AND WHY ALL FOUR MATCH
# -------------------------------------------------------
# Verbatim from the ct_plone_cookies[] header comment in src:
#
#   __ac is the stable frontend authentication cookie. Zope sessions,
#   status messages and the language override are user-specific state too. Plone
#   itself marks login/reset responses private; the URI tier is still valuable
#   when an operator weakens origin Cache-Control. Traversal views below content
#   (folder/@@edit) remain protected by the auth cookie.
#
# __ac=, _ZopeId=, statusmessages=, and I18N_LANGUAGE= are all user-specific
# state (identity cookie, session, status, language), so the presence of any
# signals a bypass. The rule is presence-only (SUFFIX match), not a value
# predicate, so an empty value or valueless cookie still triggers a bypass.
# TESTS 6-9 cover the member leak guards for each of the four cookies and the
# suffix-under-any-prefix variants.
#
# THE URI LIST AND THE /@@login TRAVERSAL VIEW
# -------------------------------------------------------
# Verified against Plone 5.2 and 6.0 source. Six URI rows are login-related
# frontends (/login, /logout, /register, /passwordreset, /mail_password,
# /manage) and one is the Plone traversal view (/@@login).
#
# /@@login is the interesting row -- it is NOT a filesystem script but a
# Traversal view, a Plone programming model that begins immediately after the
# host. Unlike regular paths, it does NOT end in .php or a segment-termination
# check (it carries the @@ prefix, which is context-bound). The byte after
# "/@@login" must be checked against the same boundary rules as a .php script:
# "/" or "." or end-of-URI. TEST 2 is the segment-termination oracle for this
# case: "/@@loginX" must CACHE (X is not '/' or '.'), and TEST 3 covers the
# positive boundary arms ("/@@login/x" and "/@@login.html") that DO bypass.
#
# ct_plone_args[] is { NULL } -- no arg rows -- and the preset row carries NULL
# in both cookie_preds and key_cookies, so this file has no arg leg, no
# predicate leg and no value-keying leg. No row is a prefix of another row
# (/logout, /register, /passwordreset, /mail_password, /manage, /@@login --
# checked pairwise), so the #222 prefix-row rule does not apply here.
#
# THE VACUOUS URI TEST TRAP
# -------------------------------------------------------
# uri_prefix() is byte-0 anchored, so a URI test served under a DIFFERENT
# location prefix (e.g. "/plone/login") never reaches the rule at all and
# would pass with the row deleted. TEST 1 puts every URI arm at the ROOT path;
# TEST 11 is the explicit negative proving "/plone/login" HITs precisely
# because the rule never fires off byte 0.
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

# Root-anchored prefix locations for every URI row. /plone/ carries the
# path-independent cookie/member-leak cases and the byte-0 vacuity control.
# /gen/ is the isolation control -- a DIFFERENT preset.
our $Config = ct_config(
    { path => '/login',      backend => 'plone' },
    { path => '/logout',     backend => 'plone' },
    { path => '/register',   backend => 'plone' },
    { path => '/passwordreset', backend => 'plone' },
    { path => '/mail_password', backend => 'plone' },
    { path => '/manage',     backend => 'plone' },
    { path => '/@@login',    backend => 'plone' },  # @@ is a Plone traversal view prefix
    { path => '/plone/',     backend => 'plone' },
    { path => '/gen/',       backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: every URI row bypasses at the root, with no cookie
# The full ct_plone_uris[] table, each on its own path so a shared key cannot
# mask a missing row.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /login",         "GET /login",
 "GET /logout",        "GET /logout",
 "GET /register",      "GET /register",
 "GET /passwordreset", "GET /passwordreset",
 "GET /mail_password",  "GET /mail_password",
 "GET /manage",        "GET /manage",
 'GET /@@login',       'GET /@@login']
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200]



=== TEST 2: SEGMENT BOUNDARY -- /@@loginX must CACHE
# "/@@login" is a traversal view prefix, so the boundary branch of
# ngx_http_cache_turbo_uri_prefix() is LIVE. The byte after the needle here is
# 'X', not '/' or '.' and not end-of-URI, so this is a different segment that
# merely shares the prefix and must cache. Served under the real /@@login
# location so the HIT cannot pass for free on an implicit 404.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
['GET /@@loginX', 'GET /@@loginX']
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 3: the two positive boundary arms still bypass
# "/@@login/extra" ('/' continuation) and "/@@login.html" ('.' continuation)
# are both inside the matched subtree per the boundary check.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
['GET /@@login/extra', 'GET /@@login/extra',
 'GET /@@login.html',  'GET /@@login.html']
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 4: __ac cookie -- the stable frontend authentication cookie
# The primary identity cookie, written on successful login. Presence triggers a
# bypass. TESTS 6 pins the member-leak guard for this row.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: __ac=YWxhZGRpbjplY2Q2MmE1YzI4YWUwNDQyNDg1YjRkY2FmYzA2ZGYyZWE=
--- request eval
["GET /plone/auth-a", "GET /plone/auth-a"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 5: _ZopeId and statusmessages and I18N_LANGUAGE also bypass
# _ZopeId= is the Zope session cookie, statusmessages= is user-specific message
# state, I18N_LANGUAGE= is the language override. All signal user-specific
# state and must bypass. Each is fetched twice; TESTS 7-9 pin the member-leak
# guards for these rows.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /plone/sess-a",  "GET /plone/sess-a",
 "GET /plone/msg-a",   "GET /plone/msg-a",
 "GET /plone/lang-a",  "GET /plone/lang-a"]
--- more_headers eval
["Cookie: _ZopeId=a1b2c3d4e5f6",
 "Cookie: _ZopeId=a1b2c3d4e5f6",
 "Cookie: statusmessages=1",
 "Cookie: statusmessages=1",
 "Cookie: I18N_LANGUAGE=de",
 "Cookie: I18N_LANGUAGE=de"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 6: member LEAK GUARD -- /logout must bypass with NO cookie
# /logout is a bypass URI from ct_plone_uris[]; the leak guard ensures it
# bypasses even without the __ac cookie present, the same safeguard as
# phorum.t TEST 4.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /logout", "GET /logout"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 7: member LEAK GUARD -- /register must bypass with NO cookie
# /register is a bypass URI from ct_plone_uris[]; the leak guard ensures it
# bypasses even without the _ZopeId cookie present.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /register", "GET /register"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 8: member LEAK GUARD -- /passwordreset must bypass with NO cookie
# /passwordreset is a bypass URI from ct_plone_uris[]; the leak guard ensures
# it bypasses even without the statusmessages cookie present.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /passwordreset", "GET /passwordreset"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 9: member LEAK GUARD -- /mail_password must bypass with NO cookie
# /mail_password is a bypass URI from ct_plone_uris[]; the leak guard ensures
# it bypasses even without the I18N_LANGUAGE cookie present.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /mail_password", "GET /mail_password"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 10: suffix-under-any-prefix -- __ac with a proxy prefix still bypasses
# Cookie matching is by SUFFIX, so a proxy- or theme-prefixed variant is still
# a login signal. A request with a prefixed __ac cookie must still bypass.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: myproxy___ac=YWxhZGRpbjplY2Q2MmE1YzI4YWUwNDQyNDg1YjRkY2FmYzA2ZGYyZWE=
--- request eval
["GET /plone/auth-prefix", "GET /plone/auth-prefix"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 11: empty __ac cookie value still bypasses
# The rule is presence-only (suffix match), not a value predicate. An empty
# cookie value is still a bypass. Fetched twice per the bypass rule.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: __ac=
--- request eval
["GET /plone/auth-empty", "GET /plone/auth-empty"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 12: bare valueless __ac cookie (no '=') does NOT bypass
# The suffix match is exactly "__ac=", ending with the '=' sign. A bare
# "Cookie: __ac" (no '=') does NOT match that suffix, so it is treated as
# a guest cookie and the request CACHES normally. The second request should HIT.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: __ac
--- request eval
["GET /plone/auth-bare", "GET /plone/auth-bare"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 13: an unrelated guest cookie does NOT bypass
# A guest-only cookie (not in the ct_plone_cookies[] list) must not trigger a
# bypass. The request should cache normally.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: PHPSESSID=abc
--- request eval
["GET /plone/topic-guest", "GET /plone/topic-guest"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 14: THE VACUOUS URI TEST -- /plone/login HITs, not byte-0
# uri_prefix() is byte-0 anchored, so a URI test served under a location whose
# path is NOT the root never reaches the rule. This proves a URI arm sent
# under /plone/ would pass for free even with the row deleted -- which is
# exactly why every URI arm in TEST 1 is sent at the true root instead.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /plone/login", "GET /plone/login"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 15: a leading non-matching cookie before a matching one
# The cookie scan must not end on the first cookie match. A request with
# multiple cookies where one is non-matching and another is matching must still
# bypass. This tests that the scan continues through the cookie header.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: PHPSESSID=guest; __ac=YWxhZGRpbjplY2Q2MmE1YzI4YWUwNDQyNDg1YjRkY2FmYzA2ZGYyZWE=
--- request eval
["GET /plone/multi-cookie", "GET /plone/multi-cookie"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 16: the plone cookies under /gen/ (wordpress backend) still HIT
# Isolation control. wordpress has its own cookie list and the plone rows do
# not leak across backends.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: __ac=YWxhZGRpbjplY2Q2MmE1YzI4YWUwNDQyNDg1YjRkY2FmYzA2ZGYyZWE=
--- request eval
["GET /gen/topic-iso", "GET /gen/topic-iso"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
