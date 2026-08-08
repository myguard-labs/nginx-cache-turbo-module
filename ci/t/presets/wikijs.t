# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Wiki.js preset (docs/wikijs.md). Ported from Python to Test::Nginx::Socket.
#
# Verbatim from the ct_wikijs_cookies[]/ct_wikijs_uris[] header comment in
# src, because it names the whole shape of this preset:
#
#   Wiki.js 2.x. Authentication is a fixed `jwt` cookie. Express-session is
#   installed globally but saveUninitialized=false leaves ordinary guests
#   cookie-free; OAuth strategies can create the default connect.sid session.
#   loginRedirect carries a private target across login. The URI tier keeps
#   identity, editor/history/source, upload and GraphQL surfaces out even
#   before a cookie exists. Published arbitrary-path pages remain available
#   for shared guest caching; their ACL/navigation view is guest-group-
#   specific, while all authenticated group variants carry jwt and bypass.
#
# ct_wikijs_args[] is { NULL } -- no arg tier, no arg tests here.
#
# THE SINGLE-LETTER ROWS -- SEGMENT-TERMINATION IS THE WHOLE POINT
# ------------------------------------------------------------------------
# Wiki.js's admin/API namespace is one character per top-level route: /a
# (admin), /d (source/diff), /e (editor), /h (history), /p (profile/
# published page shell), /s (search), /u (user). Each is a bare single-byte
# needle with no trailing slash, so ngx_http_cache_turbo_uri_prefix()'s
# boundary check ('/', '.', or end-of-URI) is doing ALL of the work: under a
# naive strncmp/prefix match, "/a" would also swallow "/about", "/api", and
# "/articles" -- a huge fraction of any real wiki's public page tree. TESTS
# 1-2 below are the positive block (exact hit, '/' continuation, '.'
# continuation) and the negative block (longer real words that merely start
# with the same letter) for every one of the seven single-letter rows.
#
# "/login" vs "/login-reset", "/graphql" vs "/graphql-subscriptions"
# ------------------------------------------------------------------------
# `-` is NOT a segment-termination byte (only '/', '.', and end-of-URI are),
# so "/login-reset" does NOT match via the "/login" row's boundary check --
# it needs, and has, its own explicit row in ct_wikijs_uris[]. Same shape for
# "/graphql" vs "/graphql-subscriptions". This is exactly the trap a "just
# use strncmp" repair of the single-letter rows above would reintroduce:
# TESTS 3-4 pin both pairs as four independently-addressed rows, not two.
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

# Root-anchored prefix locations for every URI row. /wiki/ carries the
# path-independent cookie cases. /gen/ is the isolation control -- a
# DIFFERENT preset.
our $Config = ct_config(
    { path => '/a',                     backend => 'wikijs' },
    { path => '/d',                     backend => 'wikijs' },
    { path => '/e',                     backend => 'wikijs' },
    { path => '/h',                     backend => 'wikijs' },
    { path => '/p',                     backend => 'wikijs' },
    { path => '/s',                     backend => 'wikijs' },
    { path => '/u',                     backend => 'wikijs' },
    { path => '/login',                 backend => 'wikijs' },
    { path => '/logout',                backend => 'wikijs' },
    { path => '/register',              backend => 'wikijs' },
    { path => '/verify',                backend => 'wikijs' },
    { path => '/login-reset',           backend => 'wikijs' },
    { path => '/graphql',               backend => 'wikijs' },
    { path => '/graphql-subscriptions', backend => 'wikijs' },
    { path => '/about',                 backend => 'wikijs' },
    { path => '/api',                   backend => 'wikijs' },
    { path => '/articles',              backend => 'wikijs' },
    { path => '/wiki/',                 backend => 'wikijs' },
    { path => '/gen/',                  backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: single-letter rows -- positives (exact, '/' and '.' continuation)
# Every one of the seven bare single-letter needles (/a /d /e /h /p /s /u),
# each checked at the exact path, a '/' continuation, and a '.' continuation
# -- all three are inside the matched subtree per the boundary check.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /a",         "GET /a",
 "GET /a/",        "GET /a/",
 "GET /a/pages",   "GET /a/pages",
 "GET /a.json",    "GET /a.json",
 "GET /d",         "GET /d",
 "GET /d/",        "GET /d/",
 "GET /d/pages",   "GET /d/pages",
 "GET /d.json",    "GET /d.json",
 "GET /e",         "GET /e",
 "GET /e/",        "GET /e/",
 "GET /e/pages",   "GET /e/pages",
 "GET /e.json",    "GET /e.json",
 "GET /h",         "GET /h",
 "GET /h/",        "GET /h/",
 "GET /h/pages",   "GET /h/pages",
 "GET /h.json",    "GET /h.json",
 "GET /p",         "GET /p",
 "GET /p/",        "GET /p/",
 "GET /p/pages",   "GET /p/pages",
 "GET /p.json",    "GET /p.json",
 "GET /s",         "GET /s",
 "GET /s/",        "GET /s/",
 "GET /s/pages",   "GET /s/pages",
 "GET /s.json",    "GET /s.json",
 "GET /u",         "GET /u",
 "GET /u/",        "GET /u/",
 "GET /u/pages",   "GET /u/pages",
 "GET /u.json",    "GET /u.json"]
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
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
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
 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200,
 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200,
 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200]



=== TEST 2: single-letter rows -- negatives, must stay HIT (real words, not the segment)
# "/about", "/api", "/articles" all start with the same byte as "/a" but
# continue with a letter -- neither '/' nor '.' nor end-of-URI -- so they are
# a DIFFERENT path segment entirely and must never bypass. Served under the
# real /about, /api, /articles locations so the HIT cannot pass for free on
# an implicit 404. This is the highest-value regression pin in this file: a
# naive strncmp/prefix repair of the single-letter rows would swallow all
# three.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /about",    "GET /about",
 "GET /api",      "GET /api",
 "GET /articles", "GET /articles"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 3: /login vs /login-reset -- separate rows, both bypass independently
# '-' is not a segment-termination byte, so "/login-reset" does NOT match via
# the "/login" row; it needs, and has, its own explicit row. Both are
# asserted here so a repair that collapses them back to one prefix check
# cannot pass silently.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /login",       "GET /login",
 "GET /login-reset", "GET /login-reset"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 4: /graphql vs /graphql-subscriptions -- separate rows, both bypass independently
# Same shape as TEST 3: '-' does not terminate the "/graphql" segment, so
# "/graphql-subscriptions" needs, and has, its own row.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /graphql",               "GET /graphql",
 "GET /graphql-subscriptions", "GET /graphql-subscriptions"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 5: the remaining plain-word rows bypass
# /logout, /register, /verify -- the rest of the identity/auth surface.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /logout",   "GET /logout",
 "GET /register", "GET /register",
 "GET /verify",   "GET /verify"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 6: member LEAK GUARD -- jwt bypasses, twice, non-matching cookie first
# jwt is the fixed authentication cookie. A leading non-matching cookie
# ("theme=dark") is sent alongside it so the scan cannot terminate on the
# first entry and silently skip the real match.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: theme=dark; jwt=eyJhbGciOiJIUzI1NiJ9.deadbeef
--- request eval
["GET /wiki/home", "GET /wiki/home"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 7: member LEAK GUARD -- connect.sid bypasses, twice, non-matching cookie first
# The default express-session cookie, created by OAuth strategies.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: theme=dark; connect.sid=s%3AabcDEF.ghijkl
--- request eval
["GET /wiki/oauth-home", "GET /wiki/oauth-home"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 8: member LEAK GUARD -- loginRedirect bypasses, twice, non-matching cookie first
# Carries a private post-login target across the login flow.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: theme=dark; loginRedirect=/a/secret-page
--- request eval
["GET /wiki/redirect-home", "GET /wiki/redirect-home"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 9: a suffix-under-any-prefix cookie name still bypasses
# The match is substring-on-value-name, so a proxy/theme-prefixed variant
# (e.g. "myapp_jwt=...") still carries the "jwt=" needle and is still a
# login signal.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: myapp_jwt=eyJhbGciOiJIUzI1NiJ9.deadbeef
--- request eval
["GET /wiki/prefixed-cookie", "GET /wiki/prefixed-cookie"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 10: an EMPTY cookie value still bypasses -- presence, not NONEMPTY
# "jwt=" is matched as a substring on the raw Cookie header value, so an
# empty value still contains the needle and still bypasses.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: jwt=
--- request eval
["GET /wiki/empty-jwt", "GET /wiki/empty-jwt"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 11: a bare valueless cookie (no '=') does NOT bypass
# "jwt" alone (no trailing '=') does not contain the "jwt=" needle -- an
# unreadable/malformed cookie must not be assumed a login signal by accident,
# but it also must not be silently treated as one when the literal needle
# requires the '='. This pins the exact substring the engine matches.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: jwt
--- request eval
["GET /wiki/bare-jwt", "GET /wiki/bare-jwt"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 12: cookieless request caches normally
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wiki/guest-home", "GET /wiki/guest-home"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 13: an unrelated guest cookie does NOT bypass
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: theme=dark
--- request eval
["GET /wiki/theme-guest", "GET /wiki/theme-guest"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 14: the jwt cookie under /gen/ (wordpress backend) still HITs
# Isolation control. wordpress has its own cookie list and the wikijs rows
# do not leak across backends.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: jwt=eyJhbGciOiJIUzI1NiJ9.deadbeef
--- request eval
["GET /gen/topic-iso", "GET /gen/topic-iso"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
