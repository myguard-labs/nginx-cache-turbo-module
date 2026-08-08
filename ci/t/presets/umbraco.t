# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Umbraco preset (docs/umbraco.md). Ported from test_umbraco_*() functions in
# ci/tools/test_runtime.py, all deleted by this port.
#
# THE COOKIE RULE IS PRESENCE-ONLY
# ------------------------------------------------------------------------
# Verbatim from the ct_umbraco_cookies[] header comment in src, because it
# names why this preset does NOT need value predicates:
#
#   Verified current identity channels include the configurable back-office
#   cookie (default UMB_UCONTEXT), v17+ token cookies, preview/XSRF cookies,
#   and ASP.NET Identity's member cookie. UMB_EXTLOGIN and UMB_SESSION remain
#   conservative compatibility guards for legacy/optional integrations.
#   /umbraco contains the back office and management API; ordinary content and
#   the public Delivery API are left available for caching. Sites that rename
#   the member/back-office cookies must add their configured names explicitly
#   (see docs/umbraco.md).
#
# No value predicate is needed: these are identity markers, written only on
# login or configuration change. Presence alone is sufficient and safe.
#
# COOKIE NAMES: MATCHED BY RAW SUBSTRING, NOT NAME-SUFFIX
# ------------------------------------------------------------------------
# Ten rows: UMB_UCONTEXT=, UMB_EXTLOGIN=, UMB_PREVIEW=, UMB-WEBSITE-PREVIEW-
# ACCEPT=, UMB-XSRF-V=, UMB_SESSION=, umbAccessToken, umbRefreshToken,
# umbPkceCode, .AspNetCore.Identity.Application=. Bypass cookie rows are
# matched via ngx_http_cache_turbo_cookie_has() -- a plain SUBSTRING search
# over the raw Cookie header value, not a name lookup and not a suffix-of-name
# match -- so "UMB_UCONTEXT=" matches any wire name where that string appears
# anywhere, including a dynamic prefix on the cookie name. Note that some rows
# carry a trailing '=' and some do NOT (the three
# `umb*Token`/`umbPkceCode` rows and the dotted `.AspNetCore.Identity.Application=`
# row) -- respect that difference exactly. TEST 2-6 cover 4-5 representative
# rows in depth (including TEST 2 with umbAccessToken, which has NO trailing '=',
# TEST 3 with the dotted cookie, and TEST 4 with a leading non-match), then TEST
# 7 walks the remainder compactly.
#
# THE URI LIST AND ITS ANCHOR
# ------------------------------------------------------------------------
# "/umbraco" is a segment-terminated prefix: it matches /umbraco,
# /umbraco/x, /umbraco.aspx but NOT /umbracoX. The byte after the needle must
# be '/', '.' or end-of-URI. TEST 1 puts the URI at the root. TEST 2 is the
# segment-termination negative control: "/umbracoX" must CACHE.
#
# ct_umbraco_args[] is { NULL } -- no arg rows -- so this file has no arg leg.
#
# THE VACUOUS URI TEST TRAP
# ------------------------------------------------------------------------
# uri_prefix() is byte-0 anchored, so a URI test served under a DIFFERENT
# location prefix (e.g. "/site/umbraco") never reaches the rule at all and
# would pass with the row deleted. TEST 1 puts the URI at the ROOT path; TEST
# 12 is the explicit negative proving "/site/umbraco" HITs precisely because the
# rule never fires off byte 0.
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

# Root-anchored prefix locations for the URI row, plus root-level paths for
# cookie testing. /site/ carries the path-independent cookie cases and the
# byte-0 vacuity control. /gen/ is the isolation control -- a DIFFERENT preset.
our $Config = ct_config(
    { path => '/umbraco',    backend => 'umbraco' },
    { path => '/umbracoX',   backend => 'umbraco' },
    { path => '/site/',      backend => 'umbraco' },
    { path => '/gen/',       backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: the /umbraco URI bypasses at the root, with no cookie
# The URI row must match at byte 0.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /umbraco", "GET /umbraco"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 2: SEGMENT BOUNDARY -- /umbracoX must CACHE
# "/umbraco" is the full needle with no trailing slash, so the boundary branch
# of ngx_http_cache_turbo_uri_prefix() is LIVE. The byte after the needle here
# is 'X', not '/', '.' and not end-of-URI, so this is a different path segment
# that merely shares the prefix and must cache. Served under the real /umbracoX
# location so the HIT cannot pass for free on an implicit 404.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /umbracoX", "GET /umbracoX"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 3: UMB_UCONTEXT= cookie (trailing '=') bypasses
# The backoffice default. Matched by a raw substring search, so any wire
# cookie header containing "UMB_UCONTEXT=" will match.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: UMB_UCONTEXT=s1a2b3c4d5e6f7g8
--- request eval
["GET /site/user-a", "GET /site/user-a"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 4: umbAccessToken cookie (NO trailing '=') bypasses
# v17+ token cookie, matched exactly as written (no trailing '='). The prefix
# matching sees this as a different literal than the trailing-'=' variants.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: umbAccessToken=eyJhbGc
--- request eval
["GET /site/user-b", "GET /site/user-b"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 5: .AspNetCore.Identity.Application= cookie (dotted, trailing '=')
# ASP.NET Identity member cookie. The dotted name and trailing '=' must both be
# respected exactly.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: .AspNetCore.Identity.Application=CfDJ...xyz
--- request eval
["GET /site/user-c", "GET /site/user-c"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 6: a leading non-matching cookie followed by a matching one
# The bypass cookie scan must not stop early. A leading unrelated cookie
# followed by a matching one must still detect the bypass.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: PHPSESSID=guest; UMB_SESSION=logged
--- request eval
["GET /site/user-d", "GET /site/user-d"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 7: compact walk of the remaining cookie rows
# UMB_EXTLOGIN=, UMB_PREVIEW=, UMB-WEBSITE-PREVIEW-ACCEPT=, UMB-XSRF-V=,
# umbRefreshToken, umbPkceCode. Each bypasses once, no cache hit on the second
# request (no X-Cache header both times).
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /site/other-a", "GET /site/other-a",
 "GET /site/other-b", "GET /site/other-b",
 "GET /site/other-c", "GET /site/other-c",
 "GET /site/other-d", "GET /site/other-d",
 "GET /site/other-e", "GET /site/other-e",
 "GET /site/other-f", "GET /site/other-f"]
--- more_headers eval
["Cookie: UMB_EXTLOGIN=ext_val",
 "Cookie: UMB_EXTLOGIN=ext_val",
 "Cookie: UMB_PREVIEW=prev_val",
 "Cookie: UMB_PREVIEW=prev_val",
 "Cookie: UMB-WEBSITE-PREVIEW-ACCEPT=true",
 "Cookie: UMB-WEBSITE-PREVIEW-ACCEPT=true",
 "Cookie: UMB-XSRF-V=tok_val",
 "Cookie: UMB-XSRF-V=tok_val",
 "Cookie: umbRefreshToken=refresh_val",
 "Cookie: umbRefreshToken=refresh_val",
 "Cookie: umbPkceCode=pkce_val",
 "Cookie: umbPkceCode=pkce_val"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200]



=== TEST 8: a dynamic prefix on the cookie name still bypasses
# The match is a raw substring search, so a proxy- or theme-prefixed variant
# is still a bypass signal.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: mysite_UMB_UCONTEXT=prefixed_val
--- request eval
["GET /site/prefix", "GET /site/prefix"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 9: empty cookie value still bypasses -- presence only
# No predicate exists; the rule is presence-only, so an empty value is still a
# bypass. Fail-CLOSED direction.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: UMB_UCONTEXT=
--- request eval
["GET /site/empty-value", "GET /site/empty-value"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 10: bare valueless cookie (no '=') also bypasses
# An unreadable cookie must never be assumed a guest. Using umbAccessToken
# since it has no trailing '=' in the predicate list, so a bare "umbAccessToken"
# cookie (with no '=') will match.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: umbAccessToken
--- request eval
["GET /site/bare-cookie", "GET /site/bare-cookie"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 11: an unrelated guest cookie does NOT bypass
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: PHPSESSID=guest
--- request eval
["GET /site/guest-only", "GET /site/guest-only"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 12: THE VACUOUS URI TEST -- /site/umbraco HITs, not byte-0
# uri_prefix() is byte-0 anchored, so a URI test served under a location whose
# path is NOT the root never reaches the rule. This proves a URI arm sent under
# /site/ would pass for free even with the row deleted -- which is exactly why
# the URI test in TEST 1 is sent at the true root instead.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /site/umbraco", "GET /site/umbraco"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 13: the umbraco cookie under /gen/ (wordpress backend) still HITs
# Isolation control. wordpress has its own cookie list and the umbraco rows do
# not leak across backends.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: UMB_UCONTEXT=s1a2b3c4d5e6f7g8
--- request eval
["GET /gen/topic-iso", "GET /gen/topic-iso"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
