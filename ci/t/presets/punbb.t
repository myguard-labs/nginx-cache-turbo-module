# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# PunBB preset (docs/punbb.md). Ported from test_punbb_cookie_name_default()
# in ci/tools/test_runtime.py, which is deleted by this port. The sibling
# test_punbb_phorum_uri_rules() is SHARED with the phorum preset (not yet
# ported) and stays in Python untouched -- this file duplicates its punbb-side
# URI coverage for one cycle, which is intended, not an oversight.
#
# THE COOKIE RULE IS PRESENCE-ONLY, AND WHY
# ------------------------------------------------------------------------
# Verbatim from the ct_punbb_cookies[] header comment in src, because it names
# the tempting wrong repair:
#
#   The ideal rule (base64-decode, split on '|', compare field[0] against the
#   guest literal "1") is NOT expressible by this engine's cookie_preds -- it
#   compares the RAW cookie value against a fixed literal (EQ/NE) or tests
#   non-emptiness, and PunBB's base64'd guest value carries a random
#   per-request key suffix after the "1|" (base64_encode('1|'.random_key(...))),
#   so it is never one fixed string an EQ/NE test can anchor on. This preset
#   therefore degrades to PRESENCE-only, same shape as SMF's SMFCookie: safe
#   (bypass is the correct-direction failure), but costs hit rate on guests who
#   merely touched a session-starting action.
#
# Consequently, like smf.t TEST 9/10 and UNLIKE mybb.t's opposite expectation,
# an EMPTY cookie value and a bare valueless cookie BOTH still bypass --
# presence-only fails CLOSED in both directions. TEST 8/9 pin that.
#
# COOKIE NAME: PunBB 1.4.x defaults to `forum_cookie`, and its installer offers
# a randomised `forum_cookie_<rand>`; `punbb_cookie` was the 1.2-era default and
# still appears on upgraded boards. Both are matched as SUBSTRINGS, so the
# randomised 1.4 variant is covered by the `forum_cookie` entry. Matching only
# `punbb_cookie` (as this row originally did) never fired on a stock 1.4
# install, which served cached guest pages to logged-in members -- the bug this
# preset exists to close. TEST 5/6/7 cover all three wire names.
#
# THE URI LIST, AND WHAT WAS DELIBERATELY LEFT OUT
# ------------------------------------------------------------------------
# Verified against the punbb/punbb tree at tag v1.4.4. Three rows were removed
# because NO PunBB release ships them: "/admin.php" (1.4.x keeps admin under
# the "/admin/" DIRECTORY; the 1.2-era admin_index.php-style layout is not
# expressible as a single needle here and losing it costs nothing because an
# admin is by definition logged in and the cookie tier bypasses already), and
# "/message_send.php"/"/message_delete.php" (PunBB core has no private
# messaging at all). Five real member/mutating scripts were added:
# edit.php, delete.php, moderate.php, profile.php, register.php. search.php
# and userlist.php are DELIBERATELY absent -- both are guest-reachable read
# surfaces that must stay cacheable. TEST 2 pins both as negative controls.
#
# ct_punbb_args[] is { NULL } -- no arg rows -- and the preset row carries NULL
# in both cookie_preds and key_cookies, so this file has no arg leg, no
# predicate leg and no value-keying leg. No row is a prefix of another row (no
# post/post2 pattern), so the #222 prefix-row rule does not apply here.
#
# "/login.php" IS SLASH-LESS -- THE SEGMENT-TERMINATION BRANCH IS LIVE HERE
# ------------------------------------------------------------------------
# Same shape as typo3.t's "/typo3": the byte after the needle must be '/' or
# '.' or end-of-URI. TEST 3 is the segment-termination oracle: "/login.phpZZ"
# continues with 'Z', neither a boundary byte nor EOF, so it is a different
# path segment and must CACHE. TEST 4 covers the two positive boundary arms
# ("/login.php/extra" and "/login.php.bak") that DO bypass.
#
# THE VACUOUS URI TEST TRAP
# ------------------------------------------------------------------------
# uri_prefix() is byte-0 anchored, so a URI test served under a DIFFERENT
# location prefix (e.g. "/punbb/login.php") never reaches the rule at all and
# would pass with the row deleted. TEST 1 puts every URI arm at the ROOT path;
# TEST 10 is the explicit negative proving "/punbb/login.php" HITs precisely
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

# Root-anchored prefix locations for every URI row, plus the negative-control
# root scripts (userlist.php, search.php) that are deliberately UNLISTED.
# /punbb/ carries the path-independent cookie cases and the byte-0 vacuity
# control. /gen/ is the isolation control -- a DIFFERENT preset.
our $Config = ct_config(
    { path => '/login.php',    backend => 'punbb' },
    { path => '/post.php',     backend => 'punbb' },
    { path => '/edit.php',     backend => 'punbb' },
    { path => '/delete.php',   backend => 'punbb' },
    { path => '/moderate.php', backend => 'punbb' },
    { path => '/profile.php',  backend => 'punbb' },
    { path => '/register.php', backend => 'punbb' },
    { path => '/misc.php',     backend => 'punbb' },
    { path => '/admin/',       backend => 'punbb' },
    { path => '/userlist.php', backend => 'punbb' },
    { path => '/search.php',   backend => 'punbb' },
    { path => '/punbb/',       backend => 'punbb' },
    { path => '/gen/',         backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: every URI row bypasses at the root, with no cookie
# The full ct_punbb_uris[] table, each on its own path so a shared key cannot
# mask a missing row.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /login.php",    "GET /login.php",
 "GET /post.php",     "GET /post.php",
 "GET /edit.php",     "GET /edit.php",
 "GET /delete.php",   "GET /delete.php",
 "GET /moderate.php", "GET /moderate.php",
 "GET /profile.php",  "GET /profile.php",
 "GET /register.php", "GET /register.php",
 "GET /misc.php",     "GET /misc.php",
 "GET /admin/users.php", "GET /admin/users.php"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
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
 200, 200, 200]



=== TEST 2: userlist.php and search.php stay HIT -- the per-script negative
# Deliberately unlisted guest-reachable read surfaces. A blanket "any root
# .php bypasses" bug would still pass every arm in TEST 1 while failing here.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /userlist.php", "GET /userlist.php",
 "GET /search.php",   "GET /search.php"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]



=== TEST 3: SEGMENT BOUNDARY -- /login.phpZZ must CACHE
# "/login.php" is slash-less, so the boundary branch of
# ngx_http_cache_turbo_uri_prefix() is LIVE. The byte after the needle here is
# 'Z', not '/' or '.' and not end-of-URI, so this is a different path segment
# that merely shares the prefix and must cache. Served under the real
# /login.php location so the HIT cannot pass for free on an implicit 404.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /login.phpZZ", "GET /login.phpZZ"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 4: the two positive boundary arms still bypass
# "/login.php/extra" ('/' continuation) and "/login.php.bak" ('.' continuation)
# are both inside the matched subtree per the boundary check.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /login.php/extra", "GET /login.php/extra",
 "GET /login.php.bak",   "GET /login.php.bak"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 5: the PunBB 1.4.x default cookie name bypasses
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: forum_cookie=NDJ8YWJj
--- request eval
["GET /punbb/topic-a", "GET /punbb/topic-a"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 6: the randomised 1.4 installer variant bypasses -- SUBSTRING match
# forum_cookie_9f3a1c is covered by the "forum_cookie" entry matching as a
# substring, not a full literal.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: forum_cookie_9f3a1c=NDJ8YWJj
--- request eval
["GET /punbb/topic-b", "GET /punbb/topic-b"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 7: the 1.2-era default cookie name still bypasses
# Still appears on boards upgraded from 1.2. THE BUG THIS PRESET FIXES: an
# earlier row matched only this name, so a stock 1.4 board (TEST 5) never
# fired and served cached guest pages to members.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: punbb_cookie=NDJ8YWJj
--- request eval
["GET /punbb/topic-c", "GET /punbb/topic-c"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 8: an EMPTY cookie value still bypasses -- presence, not NONEMPTY
# DELIBERATELY THE OPPOSITE of mybb.t TEST 10, same shape as smf.t TEST 9. No
# cookie_preds row exists for punbb; the rule is presence-only, so an empty
# value is still a bypass -- the fail-CLOSED direction.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: forum_cookie=
--- request eval
["GET /punbb/topic-empty", "GET /punbb/topic-empty"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 9: a bare valueless cookie (no '=') also bypasses
# Same shape as smf.t TEST 10 -- an unreadable cookie must never be assumed a
# guest.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: forum_cookie
--- request eval
["GET /punbb/topic-bare", "GET /punbb/topic-bare"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 10: a suffix-under-any-prefix cookie name still bypasses
# The match is substring-on-name, so a proxy- or theme-prefixed variant is
# still a login signal.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: myforum_cookie=x
--- request eval
["GET /punbb/topic-prefix", "GET /punbb/topic-prefix"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 11: an unrelated guest cookie does NOT bypass
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: PHPSESSID=abc
--- request eval
["GET /punbb/topic-guest", "GET /punbb/topic-guest"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 12: THE VACUOUS URI TEST -- /punbb/login.php HITs, not byte-0
# uri_prefix() is byte-0 anchored, so a URI test served under a location whose
# path is NOT the root never reaches the rule. This proves a URI arm sent
# under /punbb/ would pass for free even with the row deleted -- which is
# exactly why every URI arm in TEST 1 is sent at the true root instead.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /punbb/login.php", "GET /punbb/login.php"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 13: the punbb cookie under /gen/ (wordpress backend) still HITs
# Isolation control. wordpress has its own cookie list and the punbb rows do
# not leak across backends.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: forum_cookie=NDJ8YWJj
--- request eval
["GET /gen/topic-iso", "GET /gen/topic-iso"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
