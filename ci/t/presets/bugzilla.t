# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Bugzilla preset (docs/bugzilla.md). Ported from multiple tests in
# ci/tools/test_runtime.py -- test_bugzilla_cookie_login_signal(),
# test_bugzilla_api_key_query_bypass(), and parts of
# test_bugzilla_rest_cgi_uri_rules() -- now deleted by this port.
#
# BUGZILLA COOKIE SIGNALS AND THEIR INDEPENDENCE
# -----------------------------------------------
# Verbatim from the ct_bugzilla_cookies[] header comment in src:
#
#   Bugzilla_login and Bugzilla_logincookie are both issued on every
#   successful cookie login (remember-me changes only expiry), so they are clean
#   member-only signals. API keys and tokens can authenticate entirely through
#   the query string. The URI list keeps login/account/mutation/admin/API entry
#   points out before a cookie exists while leaving show_bug.cgi, buglist.cgi
#   and reports cacheable for anonymous readers.
#
# Both cookies are always issued on successful login but are INDEPENDENT:
# `Bugzilla_logincookie=` does NOT end in `Bugzilla_login=`, so both rows
# fire separately. TESTS 5 and 6 verify each cookie independently bypasses;
# TEST 7 confirms a leading non-matching cookie does not prevent a trailing
# matching one from firing.
#
# ct_bugzilla_args[] is 8 rows deep, testing query-string API authentication.
# This file covers a REPRESENTATIVE sample (4 args) plus negative controls
# (TESTS 11/12 verify that an unrelated query arg does not bypass, and
# presence of unrelated args does not suppress a bypassing arg).
#
# THE URI LIST: /rest IS THE SEGMENT-TERMINATION BOUNDARY
# --------------------------------------------------------
# Verbatim from the ct_bugzilla_uris[] header comment in src:
#
#   The URI list keeps login/account/mutation/admin/API entry points out
#   before a cookie exists while leaving show_bug.cgi, buglist.cgi
#   and reports cacheable for anonymous readers.
#
# "/rest" IS SLASH-LESS (no ".cgi" suffix), so it is the highest-value
# segment-termination test in this file. It matches "/rest", "/rest/bug",
# "/rest.cgi" -- but NOT "/restaurant". TEST 4 is the explicit negative
# proving that "/restaurant" CACHES while "/rest" itself bypasses.
#
# TEST 1 covers a representative handful of URI rows (3-5) at the root;
# TEST 2 is the member LEAK GUARD for the bypassable URIs.
#
# THE VACUOUS URI TEST TRAP
# --------------------------
# uri_prefix() is byte-0 anchored, so a URI test served under a DIFFERENT
# location prefix (e.g. "/bugzilla/admin.cgi") never reaches the rule at all
# and would pass with the row deleted. TEST 13 is the explicit negative proving
# "/bugzilla/admin.cgi" HITs precisely because the rule never fires off byte 0.
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

# Root-anchored prefix locations for every URI row (sample). /bugzilla/
# carries the path-independent cookie/arg cases and the byte-0 vacuity
# control. /gen/ is the isolation control -- a DIFFERENT preset.
our $Config = ct_config(
    { path => '/admin.cgi',       backend => 'bugzilla' },
    { path => '/enter_bug.cgi',   backend => 'bugzilla' },
    { path => '/post_bug.cgi',    backend => 'bugzilla' },
    { path => '/process_bug.cgi', backend => 'bugzilla' },
    { path => '/rest',            backend => 'bugzilla' },
    { path => '/restaurant',      backend => 'bugzilla' },
    { path => '/userprefs.cgi',   backend => 'bugzilla' },
    { path => '/token.cgi',       backend => 'bugzilla' },
    { path => '/bugzilla/',       backend => 'bugzilla' },
    { path => '/gen/',            backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: representative URI rows bypass at the root, with no cookie
# A sample of ct_bugzilla_uris[] covering different mutation points:
# login/account/mutation/admin. All bypassed with no cookie present.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /admin.cgi",       "GET /admin.cgi",
 "GET /enter_bug.cgi",   "GET /enter_bug.cgi",
 "GET /post_bug.cgi",    "GET /post_bug.cgi",
 "GET /userprefs.cgi",   "GET /userprefs.cgi",
 "GET /process_bug.cgi", "GET /process_bug.cgi"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200, 200, 200]



=== TEST 2: SEGMENT BOUNDARY -- /restaurant must CACHE
# "/rest" is slash-less and matches as a URI prefix with segment termination.
# The byte after "/rest" in "/restaurant" is 'a', neither '/' nor '.' nor
# end-of-URI, so this is a different path segment that merely shares the prefix
# and must cache. Served under the real /restaurant location so the HIT cannot
# pass for free on an implicit 404. This proves the segment-termination oracle
# is live: /rest bypasses, /restaurant caches.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /restaurant", "GET /restaurant"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 3: /rest itself bypasses (the positive arm of the boundary test)
# "/rest" matches as a URI prefix with no suffix to check the boundary for,
# so it bypasses. This is the inverse of TEST 2 and proves both arms fire.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /rest", "GET /rest"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 4: /rest.cgi also bypasses -- the boundary '.' continuation
# "/rest.cgi" is inside the matched subtree per the boundary check ('.').
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /rest.cgi", "GET /rest.cgi"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 5: member LEAK GUARD -- URIs bypass with NO cookie present
# These mutation/admin/API URIs authorize per request through the database
# or API credentials (cookies or query args); caching them replays one
# member's response to every later requester, permission check skipped.
# The leak is per-URI, not cookie-gated, so this is asserted with no Cookie
# header at all -- the second fetch must also lack X-Cache (a bypass and a
# first-time MISS both lack X-Cache).
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /token.cgi?format=json", "GET /token.cgi?format=json"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 6: Bugzilla_login cookie bypasses
# One of the two login cookies -- issued on every successful cookie login.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: Bugzilla_login=alice@example.com
--- request eval
["GET /bugzilla/show-a", "GET /bugzilla/show-a"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 7: Bugzilla_logincookie bypasses independently
# The second login cookie -- also issued on every successful cookie login but
# NOT a suffix of Bugzilla_login, so it is a separately reachable row.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: Bugzilla_logincookie=9ff5c4c4e85a95e8
--- request eval
["GET /bugzilla/show-b", "GET /bugzilla/show-b"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 8: matching cookie after non-matching cookie fires the rule
# A leading non-matching cookie followed by a matching one. The matcher must
# not terminate on the first cookie. This proves the scan does not short-
# circuit on a non-match.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: PHPSESSID=x; Bugzilla_login=alice@example.com
--- request eval
["GET /bugzilla/show-c", "GET /bugzilla/show-c"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 9: Bugzilla_api_key query arg bypasses
# First of four representative API auth args (total is 8). The arg must
# trigger a bypass even without a cookie.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /bugzilla/api-a?Bugzilla_api_key=xyz", "GET /bugzilla/api-a?Bugzilla_api_key=xyz"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 10: api_key (bare name) query arg also bypasses
# Plain "api_key" without the Bugzilla_ prefix also authenticates.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /bugzilla/api-b?api_key=123", "GET /bugzilla/api-b?api_key=123"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 11: Bugzilla_token arg bypasses
# Third representative arg -- form/token-based auth.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /bugzilla/api-c?Bugzilla_token=abc123", "GET /bugzilla/api-c?Bugzilla_token=abc123"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 12: unrelated query arg does NOT bypass
# A query arg that is not in the ct_bugzilla_args[] table does not trigger
# a bypass. This proves the arg-list specificity is working.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /bugzilla/generic?something=value", "GET /bugzilla/generic?something=value"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 13: an unrelated arg alongside a matching arg still triggers bypass
# A non-matching arg in the query string must not suppress a matching one.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /bugzilla/mixed?foo=bar&api_key=456", "GET /bugzilla/mixed?foo=bar&api_key=456"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 14: an unrelated guest cookie does NOT bypass
# A cookie that is not in the ct_bugzilla_cookies[] table and carries no
# query arg does not trigger a bypass. This is the baseline negative control
# for the cookie list.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: PHPSESSID=abc
--- request eval
["GET /bugzilla/topic-guest", "GET /bugzilla/topic-guest"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 15: THE VACUOUS URI TEST -- /bugzilla/admin.cgi HITs, not byte-0
# uri_prefix() is byte-0 anchored, so a URI test served under a location
# whose path is NOT the root never reaches the rule. This proves a URI arm
# sent under /bugzilla/ would pass for free even with the row deleted --
# which is exactly why every URI arm in TEST 1 is sent at the true root instead.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /bugzilla/admin.cgi", "GET /bugzilla/admin.cgi"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 16: the bugzilla cookies under /gen/ (wordpress backend) still HIT
# Isolation control. wordpress has its own cookie list and the bugzilla rows
# do not leak across backends.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: Bugzilla_login=alice@example.com
--- request eval
["GET /gen/topic-iso", "GET /gen/topic-iso"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
