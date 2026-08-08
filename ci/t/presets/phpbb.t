# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# phpBB preset (docs/phpbb.md). Ported from test_phpbb_preset() and
# test_cookie_pred_multiple_matching_cookies() in ci/tools/test_runtime.py.
#
# URI + ?sid= rules, PLUS the cookie VALUE predicate <prefix>_u != 1.
#
# phpBB sets _u/_k/_sid for every non-bot visitor INCLUDING guests, so a
# presence matcher identifies nobody: an anon gets _u=1 (ANONYMOUS), a member
# gets _u=<user_id> (never 1 -- ANONYMOUS is a reserved row). Only a VALUE test
# separates them. Until that existed the preset shipped no cookie rule and a
# logged-in member's page was cached and served to strangers unless the
# operator hand-wrote a bypass; this file asserts that leak is closed.
#
# The name is matched by SUFFIX because the prefix is config('cookie_name'),
# an ACP setting (default "phpbb") that installers randomise -- a literal-name
# rule stops firing on a renamed board, and a bypass that stops firing leaks.
# Verified against phpbb/phpbb: includes/constants.php (ANONYMOUS=1),
# phpbb/session.php session_create()/set_cookie().
#
# See ci/t/presets/xenforo.t for why every bypass case is fetched TWICE and why
# these are `--- request eval` arrays rather than `--- pipelined_requests`.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

# /ucp.php is a ROOT location: the preset's URI rules are prefixes anchored at
# byte 0. /phpbb/ carries the cookie cases, which are path-independent.
our $Config = ct_config(
    { path => '/ucp.php', backend => 'phpbb' },
    { path => '/phpbb/',  backend => 'phpbb' },
);

run_tests();

__DATA__

=== TEST 1: /ucp.php bypasses on the URI rule
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /ucp.php", "GET /ucp.php"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 2: /ucp.php?mode=login bypasses
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /ucp.php?mode=login", "GET /ucp.php?mode=login"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 3: ?sid= bypasses -- a session-propagated URL
# Also a key-poisoning vector: the sid is per-session, so storing under it
# would mint an entry per visitor.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /phpbb/viewtopic?sid=deadbeef", "GET /phpbb/viewtopic?sid=deadbeef"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 4: guest cookies (_u=1 = ANONYMOUS) must stay cacheable
# Every anonymous phpBB visitor carries _sid/_u/_k. A presence matcher here
# would bypass essentially 100% of traffic and silently disable the cache.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: phpbb3_sid=abc; phpbb3_u=1; phpbb3_k=
--- request eval
["GET /phpbb/viewtopic-a", "GET /phpbb/viewtopic-a"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 5: a logged-in member (_u=42 != ANONYMOUS 1) MUST bypass -- THE LEAK GUARD
# Before the value predicate the member's page was cached and served to
# strangers -- a cross-user leak the docs told the operator to patch by hand.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: phpbb3_sid=abc; phpbb3_u=42; phpbb3_k=beef
--- request eval
["GET /phpbb/viewtopic-b", "GET /phpbb/viewtopic-b"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 6: the cookie NAME is matched by SUFFIX -- member, arbitrary prefix
# config 'cookie_name' is an ACP setting (default "phpbb") and installers
# randomise it. A literal-name rule silently stops firing on a renamed board,
# and a bypass rule that stops firing LEAKS.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /phpbb/vt-phpbb",     "GET /phpbb/vt-phpbb",
 "GET /phpbb/vt-phpbb3",    "GET /phpbb/vt-phpbb3",
 "GET /phpbb/vt-myboard",   "GET /phpbb/vt-myboard",
 "GET /phpbb/vt-zz",        "GET /phpbb/vt-zz"]
--- more_headers eval
["Cookie: phpbb_sid=abc; phpbb_u=7",           "Cookie: phpbb_sid=abc; phpbb_u=7",
 "Cookie: phpbb3_sid=abc; phpbb3_u=7",         "Cookie: phpbb3_sid=abc; phpbb3_u=7",
 "Cookie: myboard_xyz_sid=abc; myboard_xyz_u=7", "Cookie: myboard_xyz_sid=abc; myboard_xyz_u=7",
 "Cookie: zz_sid=abc; zz_u=7",                 "Cookie: zz_sid=abc; zz_u=7"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200]



=== TEST 7: the SUFFIX match still recognises a guest under any prefix
# The negative half of TEST 6: if the suffix rule were over-broad and bypassed
# on the NAME alone, these would bypass too and the board's hit rate is zero.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /phpbb/vg-phpbb",   "GET /phpbb/vg-phpbb",
 "GET /phpbb/vg-myboard", "GET /phpbb/vg-myboard"]
--- more_headers eval
["Cookie: phpbb_sid=abc; phpbb_u=1",             "Cookie: phpbb_sid=abc; phpbb_u=1",
 "Cookie: myboard_xyz_sid=abc; myboard_xyz_u=1", "Cookie: myboard_xyz_sid=abc; myboard_xyz_u=1"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]



=== TEST 8: no _u cookie at all stays cacheable
# The predicate must have NO OPINION when its cookie is missing, not bypass
# everything. Absent _u => no session => guest.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: other=1; unrelated=x
--- request eval
["GET /phpbb/viewtopic-c", "GET /phpbb/viewtopic-c"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 9: a valueless '_u' (no '=') fails CLOSED to bypass
# A bare "_u" gives us no value to test; guessing "guest" there would cache a
# possible member. An unreadable cookie must never be assumed to be a guest.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: phpbb3_sid=abc; phpbb3_u
--- request eval
["GET /phpbb/viewtopic-d", "GET /phpbb/viewtopic-d"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 10: "_u=10" is user 10, not ANONYMOUS(1) -- must bypass
# The compare is exact + length-checked, not a prefix.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: phpbb3_u=10
--- request eval
["GET /phpbb/viewtopic-e", "GET /phpbb/viewtopic-e"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 11: an empty value "_u=" bypasses (cleared/malformed, safe direction)
# Distinct from the bare "_u" of TEST 9: this reaches the value compare with a
# zero-length value. By the letter of "!= 1" an empty string is a non-member.
# Exercises the empty-value arm of the NE predicate.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: phpbb3_sid=abc; phpbb3_u=
--- request eval
["GET /phpbb/viewtopic-f", "GET /phpbb/viewtopic-f"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 12: a member behind a guest in the SAME header must still bypass
# THE REGRESSION. One browser visiting two boards on the same host sends
# `phpbb3_<a>_u` AND `phpbb3_<b>_u` in a single header. The evaluator used to
# return on the FIRST pair whose name matched, so a leading guest `_u=1` decided
# the whole request and masked a member `_u=42` sitting behind it -- the
# member's page was cached and served to strangers.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: phpbb3_aaa_u=1; phpbb3_bbb_u=42
--- request eval
["GET /phpbb/multi-a", "GET /phpbb/multi-a"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 13: member first also bypasses (symmetry)
# This order worked before the fix too; kept so the pair is symmetric and a
# future change cannot pass by handling only one direction.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: phpbb3_bbb_u=42; phpbb3_aaa_u=1
--- request eval
["GET /phpbb/multi-b", "GET /phpbb/multi-b"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 14: TWO guest cookies must NOT become a bypass
# `continue` means "no opinion" -- it must not leak into "objection". Without
# this arm the multi-cookie fix would trade a leak for a board-wide hit-rate
# collapse and nothing would catch it.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: phpbb3_aaa_u=1; phpbb3_bbb_u=1
--- request eval
["GET /phpbb/multi-c", "GET /phpbb/multi-c"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
