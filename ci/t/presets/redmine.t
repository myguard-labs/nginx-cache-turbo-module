# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Redmine preset (docs/redmine.md). Ported from test_redmine_cookie_and_arg_tiers()
# in ci/tools/test_runtime.py, which is deleted by this port.
#
# THE COOKIE TIER IS PRESENCE-ONLY, AND SAFELY SO
# -----------------------------------------------
# Verbatim from the ct_redmine_cookies[] header comment in src, because it
# names why this preset does NOT need a value-predicate:
#
#   `_redmine_session` is a hardcoded string literal in config/application.rb
#   (config.session_store :cookie_store, :key => '_redmine_session') — not
#   derived from config, unlike most of the apps researched alongside it.
#   `autologin` is the remember-me cookie; its name is config-settable
#   (Redmine::Configuration['autologin_cookie_name']) but falls back to the
#   literal, so the stock name is matched and a renamed one degrades to
#   "session cookie still catches an active login" rather than to nothing.
#
# THE ARG TIER IS LOAD-BEARING AND NOT OPTIONAL
# -----------------------------------------------
# Verbatim from the ct_redmine_uris[] header comment in src:
#
#   `key` authenticates with NO cookie at all: application_controller.rb
#   accepts it as an Atom key (params[:format] == 'atom' && params[:key] ->
#   User.find_by_atom_key) and as an API key (api_key_from_request when
#   Setting.rest_api_enabled?). A cookie-only rule would therefore cache a
#   private issue list fetched via ?key=<atom key> under the public cache key
#   and serve it to everyone. This is the same class of hole the ghost
#   preset's ?uuid=/?key=/?gift= rows close.
#
# THE URI TIER IS DELIBERATELY NARROW
# ------------------------------------
# The URI tier deliberately does NOT list /projects, /issues, /news, /wiki or
# /repository. On an open tracker those are the main public content and the
# entire reason to cache it; public-vs-private there is a per-project ACL that
# nginx cannot see, and the cookie rule is what protects a logged-in view of
# them. Verified against redmine/redmine master (7.0.0 current 2026-07-26).
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

# Root-anchored prefix locations for every URI row. /redmine/ carries the
# path-independent cookie and arg cases and the byte-0 vacuity control.
# /gen/ is the isolation control -- a DIFFERENT preset.
our $Config = ct_config(
    { path => '/admin',        backend => 'redmine' },
    { path => '/my',           backend => 'redmine' },
    { path => '/login',        backend => 'redmine' },
    { path => '/logout',       backend => 'redmine' },
    { path => '/account',      backend => 'redmine' },
    { path => '/settings',     backend => 'redmine' },
    { path => '/enumerations', backend => 'redmine' },
    { path => '/roles',        backend => 'redmine' },
    { path => '/trackers',     backend => 'redmine' },
    { path => '/custom_fields',backend => 'redmine' },
    { path => '/auth_sources', backend => 'redmine' },
    { path => '/mail_handler', backend => 'redmine' },
    { path => '/redmine/',     backend => 'redmine' },
    { path => '/gen/',         backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: every URI row bypasses at the root, with no cookie
# The full ct_redmine_uris[] table, each on its own path so a shared key
# cannot mask a missing row.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /admin",        "GET /admin",
 "GET /my",           "GET /my",
 "GET /login",        "GET /login",
 "GET /logout",       "GET /logout",
 "GET /account",      "GET /account",
 "GET /settings",     "GET /settings",
 "GET /enumerations", "GET /enumerations",
 "GET /roles",        "GET /roles",
 "GET /trackers",     "GET /trackers",
 "GET /custom_fields","GET /custom_fields",
 "GET /auth_sources", "GET /auth_sources",
 "GET /mail_handler", "GET /mail_handler"]
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
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200,
 200, 200, 200, 200, 200, 200, 200, 200, 200]



=== TEST 2: SEGMENT BOUNDARY -- /logins must CACHE
# "/login" is slash-less, so the boundary branch of
# ngx_http_cache_turbo_uri_prefix() is LIVE. The byte after the needle here
# is 's', not '/' or '.' and not end-of-URI, so this is a different path
# segment that merely shares the prefix and must cache.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /logins", "GET /logins"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 3: the two positive boundary arms still bypass
# "/login/" ('/' continuation) and "/login.bak" ('.' continuation)
# are both inside the matched subtree per the boundary check.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /login/extra", "GET /login/extra",
 "GET /login.bak",   "GET /login.bak"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 4: key argument -- fetch without a key first, then with key
# `key` is an Atom key or API key that authenticates with NO cookie at all.
# A cookie-only rule would cache a private resource under the public key and
# serve it to everyone. Both requests must bypass.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /redmine/item?key=private", "GET /redmine/item?key=private"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 5: NEGATIVE -- unrelated arg does NOT bypass
# Verify that only the `key` arg causes a bypass, not any arg.
#
# A DISTINCT path from TEST 4 on purpose. cache_turbo_key is $uri (see
# ci/t/lib/CacheTurbo.pm), so the query string is not part of the cache key:
# on the shared /redmine/item path this block's MISS-then-HIT held only
# because TEST 4 bypasses and therefore stores nothing. That made a real
# assertion depend on block ORDER rather than on the behaviour under test --
# reorder the file, or make TEST 4 ever cache, and this goes red for a reason
# that has nothing to do with arg matching.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /redmine/item-noarg?other=val", "GET /redmine/item-noarg?other=val"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 6: member LEAK GUARD -- bypass URIs carry no cookie
# Some URI rows in Redmine (this block uses /account) are sensitive and must
# bypass regardless of cookies. This verifies the leak guard: even a URI row must
# bypass TWICE with no cookie present at all, and X-Cache must be absent both
# times.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /account?id=7", "GET /account?id=7"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 7: substring-under-any-prefix -- _redmine_session with a prefix
# The cookie match is substring-on-name, so a proxy- or theme-prefixed variant
# (e.g., `theme__redmine_session`) is still a login signal.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: theme__redmine_session=abc123def456
--- request eval
["GET /redmine/admin-iso", "GET /redmine/admin-iso"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 8: empty cookie value still bypasses
# `_redmine_session` is present-only (no value predicate), so an empty value
# is still a bypass.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: _redmine_session=
--- request eval
["GET /redmine/topic-empty", "GET /redmine/topic-empty"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 9: bare valueless cookie (no '=') does NOT match -- CACHES
# The substring `_redmine_session=` (with '=') does not match a bare cookie
# name like `_redmine_session` (no '='). This is a difference from punbb/smf,
# which match bare names like `forum_cookie`. A bare valueless cookie here does
# NOT trigger bypass.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: _redmine_session
--- request eval
["GET /redmine/topic-bare", "GET /redmine/topic-bare"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 10: both Redmine session cookies
# `_redmine_session` and `autologin` (remember-me) both trigger bypass.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /redmine/read-a", "GET /redmine/read-a",
 "GET /redmine/read-b", "GET /redmine/read-b"]
--- more_headers eval
["Cookie: _redmine_session=42:deadbeef",
 "Cookie: _redmine_session=42:deadbeef",
 "Cookie: autologin=user_token_xyz",
 "Cookie: autologin=user_token_xyz"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 11: an unrelated guest cookie does NOT bypass
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: PHPSESSID=abc
--- request eval
["GET /redmine/topic-guest", "GET /redmine/topic-guest"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 12: THE VACUOUS URI TEST -- /redmine/admin HITs, not byte-0
# uri_prefix() is byte-0 anchored, so a URI test served under a location whose
# path is NOT the root never reaches the rule. This proves a URI arm sent under
# /redmine/ would pass for free even with the row deleted -- which is exactly
# why every URI arm in TEST 1 is sent at the true root instead.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /redmine/admin", "GET /redmine/admin"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 13: the redmine cookie under /gen/ (wordpress backend) still HITs
# Isolation control. wordpress has its own cookie list and the redmine rows do
# not leak across backends.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: _redmine_session=42:deadbeef
--- request eval
["GET /gen/topic-iso", "GET /gen/topic-iso"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
