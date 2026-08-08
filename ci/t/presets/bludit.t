# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Bludit preset (docs/bludit.md). Ported from no existing Python tests in
# ci/tools/test_runtime.py -- a new test tier closing the suite's bludit
# gap. The public bootstrap is session-free; only the admin bootstrap starts
# a session. The __Secure- spelling still contains BLUDIT-KEY, so suffix/
# substring matching buys the dual-interface support one write.
#
# THE COOKIE RULE IS PRESENCE-ONLY
# ------------------------------------------------------------------------
# Verbatim from the ct_bludit_cookies[] header comment in src:
#
#   Only the admin bootstrap starts the BLUDIT-KEY session; the public
#   bootstrap is session-free. The __Secure- spelling still contains BLUDIT-KEY,
#   and the two remember-me names are stable literals. /install.php is dynamic
#   setup state and must never be replayed from the page cache.
#
# The presence-only rule is safe: guests never receive any of these three
# cookies (BLUDIT-KEY, BLUDITREMEMBERUSERNAME, BLUDITREMEMBERTOKEN), so a
# bypass on presence alone never serves a guest page to a member. Empty values
# and bare valueless cookies still bypass -- presence-only fails CLOSED in both
# directions. TESTS 8/9 pin that.
#
# THE URI LIST
# ------------------------------------------------------------------------
# /admin is the root SEGMENT (admin panel), bytewise prefix-matched but
# SEGMENT-TERMINATED: /admin/ and /admin.php continue as segments, but
# /administrator does not. /install.php is the setup script and must never
# cache. No args are bypass-gated, so ct_bludit_args[] = { NULL }.
#
# TEST 3 is the segment-termination oracle: "/administratorZZ" continues with
# 'Z', neither a boundary byte nor EOF, so it is a different path that merely
# shares the prefix and must CACHE. The positive arms ("/admin/" and "/admin.php")
# are covered elsewhere as regular-routed admin paths.
#
# THE COOKIE NAMING DISTINCTION -- NO TRAILING '='
# ------------------------------------------------------------------------
# Note BLUDIT-KEY has NO trailing '=' in the ct_bludit_cookies[] table while
# the other two do: "BLUDITREMEMBERUSERNAME=" and "BLUDITREMEMBERTOKEN=". This
# is the RAW spelling the source carries and MUST be tested exactly as written.
# Substring matching means "BLUDIT-KEY" matches the prefixed spelling
# "__Secure-BLUDIT-KEY" on the wire, and "BLUDITREMEMBERUSERNAME=" (with '=')
# matches only the named variant, not a bare "BLUDITREMEMBERUSERNAME" (no '=').
# TEST 6 verifies the prefixed spelling. TESTS 8/9 verify empty/bare value
# handling of the '=' variants.
#
# THE VACUOUS URI TEST TRAP
# ------------------------------------------------------------------------
# uri_prefix() is byte-0 anchored, so a URI test served under a DIFFERENT
# location prefix (e.g. "/bludit/admin") never reaches the rule at all and
# would pass with the row deleted. TEST 1 puts every URI arm at the ROOT
# path; TEST 12 is the explicit negative proving "/bludit/admin" HITs precisely
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

# Root-anchored prefix locations for every URI row. /bludit/ carries the
# path-independent cookie/bare/empty-value cases and the byte-0 vacuity control.
# /gen/ is the isolation control -- a DIFFERENT preset.
our $Config = ct_config(
    { path => '/admin',      backend => 'bludit' },
    { path => '/install.php', backend => 'bludit' },
    { path => '/bludit/',     backend => 'bludit' },
    { path => '/gen/',        backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: both URI rows bypass at the root, with no cookie
# The full ct_bludit_uris[] table, each on its own path so a shared key
# cannot mask a missing row.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /admin", "GET /admin",
 "GET /install.php", "GET /install.php"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 2: /install.php/extra and /install.php.bak both bypass (segment boundary)
# /install.php is slash-less, so the boundary branch of
# ngx_http_cache_turbo_uri_prefix() is LIVE. Both "/install.php/" (slash
# continuation) and "/install.php.bak" (dot continuation) are inside the
# matched subtree per the segment boundary check.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /install.php/extra", "GET /install.php/extra",
 "GET /install.php.bak",   "GET /install.php.bak"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 3: SEGMENT BOUNDARY -- /administratorZZ must CACHE
# "/admin" is segment-terminated, so the byte after the needle must be '/' or
# '.' or end-of-URI. "/administratorZZ" continues with 'Z', neither a boundary
# byte nor EOF, so it is a different path segment that merely shares the prefix
# and must CACHE. Served under the /admin location so the HIT cannot pass for
# free on an implicit 404.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /administratorZZ", "GET /administratorZZ"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 4: BLUDIT-KEY cookie bypasses
# The primary session cookie. Substring match, so catches the wire name as is.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: BLUDIT-KEY=deadbeef42
--- request eval
["GET /bludit/topic-a", "GET /bludit/topic-a"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 5: BLUDITREMEMBERUSERNAME= cookie bypasses
# Remember-me cookie (note the trailing '=' in the table name).
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: BLUDITREMEMBERUSERNAME=alice
--- request eval
["GET /bludit/topic-b", "GET /bludit/topic-b"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 6: BLUDITREMEMBERTOKEN= cookie bypasses
# Remember-me token cookie (note the trailing '=' in the table name).
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: BLUDITREMEMBERTOKEN=abc123xyz
--- request eval
["GET /bludit/topic-c", "GET /bludit/topic-c"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 7: __Secure-BLUDIT-KEY prefixed spelling still bypasses
# The BLUDIT-KEY entry is a substring match, so the __Secure- prefix is
# transparent to the matcher -- the wire name still contains BLUDIT-KEY.
# Regression pin for dual-interface support.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: __Secure-BLUDIT-KEY=token99
--- request eval
["GET /bludit/topic-secure", "GET /bludit/topic-secure"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 8: empty BLUDITREMEMBERUSERNAME= value still bypasses
# Presence-only; empty value is still a bypass -- fail-CLOSED direction.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: BLUDITREMEMBERUSERNAME=
--- request eval
["GET /bludit/topic-empty", "GET /bludit/topic-empty"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 9: bare valueless BLUDITREMEMBERUSERNAME (no '=') does NOT bypass
# The table has "BLUDITREMEMBERUSERNAME=" with '=', a substring of the cookie
# NAME. A bare cookie has just the name, no '=' suffix on the wire, so it does
# not match the entry. This is the deliberate asymmetry: the '=' in the source
# is load-bearing.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: BLUDITREMEMBERUSERNAME
--- request eval
["GET /bludit/topic-bare", "GET /bludit/topic-bare"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 10: non-matching cookie does NOT bypass
# A guest cookie that is not in the bypass list.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: PHPSESSID=abc
--- request eval
["GET /bludit/topic-guest", "GET /bludit/topic-guest"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 11: leading non-matching cookie followed by matching cookie -- still bypasses
# A bypass cookie must never end the cookie scan. A non-matching cookie first,
# then a matching one, must still trigger the bypass.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: PHPSESSID=abc; BLUDIT-KEY=xyz
--- request eval
["GET /bludit/topic-multi", "GET /bludit/topic-multi"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 12: THE VACUOUS URI TEST -- /bludit/admin HITs, not byte-0
# uri_prefix() is byte-0 anchored, so a URI test served under a location whose
# path is NOT the root never reaches the rule. This proves a URI arm sent
# under /bludit/ would pass for free even with the row deleted -- which is
# exactly why every URI arm in TEST 1 is sent at the true root instead.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /bludit/admin", "GET /bludit/admin"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 13: the bludit cookies under /gen/ (wordpress backend) still HITs
# Isolation control. wordpress has its own cookie list and the bludit rows
# do not leak across backends.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: BLUDIT-KEY=xyz
--- request eval
["GET /gen/topic-iso", "GET /gen/topic-iso"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
