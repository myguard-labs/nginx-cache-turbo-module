# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# XenForo preset (docs/xenforo.md). Ported from test_xenforo_preset() and
# test_xenforo_not_in_generic() in ci/tools/test_runtime.py.
#
# xf_session MUST BYPASS, and that assertion is INVERTED from the original
# preset on purpose. It is the regression guard for a real cross-user leak.
#
# STOCK XF2 HAS NO LOGIN-ONLY COOKIE. xf_user is the REMEMBER-ME cookie only
# (completeLogin() mints it inside `if ($remember)`, and "Stay logged in" is
# unticked by default), so an ordinary member who just types their password
# carries ONLY xf_session. This test used to assert that xf_session "must stay
# cacheable" -- which meant that member's authenticated page was stored and
# served to strangers. Bypassing on xf_session is the only cookie-only fix; it
# costs hit rate (XF's session is lazy, so clean guests still cache, but a
# guest who logs out / trips 2FA / hits a captcha acquires one) and that is the
# trade.
#
# Do not "optimise" xf_session back out. That is the leak.
#
# READING THE ASSERTIONS
# ----------------------
# A BYPASS and a first-time MISS are indistinguishable on a single request:
# both answer with no X-Cache header. Every bypass case therefore issues the
# SAME request TWICE and asserts the header is absent BOTH times -- only a
# bypass is still header-less on the second request; a mere MISS would have
# been stored and would answer HIT.
#
# The requests are `--- request eval` ARRAYS, not `--- pipelined_requests`.
# A pipelined batch arrives in one read() with no event-loop turn between the
# requests, which is the wrong shape for warm-then-read cache traffic; each
# array entry opens its own connection and completes its own round trip.
# See memory/lessons/feedback-pipelined-batch-gives-async-seeder-no-event-loop-turns.md

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

# /login, /misc and /api/ are ROOT locations: the preset's URI rules are
# prefixes anchored at byte 0, so they cannot be exercised from below a mount.
# /xf/ carries the cookie and arg cases, which are path-independent.
# /gen/ is the isolation control -- a DIFFERENT preset (wordpress), proving the
# xenforo rows are opt-in and do not leak into another backend's location.
our $Config = ct_config(
    { path => '/login',  backend => 'xenforo'   },
    { path => '/misc',   backend => 'xenforo'   },
    { path => '/api/',   backend => 'xenforo'   },
    { path => '/xf/',    backend => 'xenforo'   },
    { path => '/gen/',   backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: /login bypasses on the URI rule
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /login", "GET /login"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 2: /misc/style bypasses on the URI rule
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /misc/style", "GET /misc/style"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 3: /api/ bypasses -- it authenticates on the XF-Api-Key HEADER
# Invisible to every cookie rule, so a shared cache keyed on URL alone would
# serve one API client's private response to the next. It MUST bypass on the URI.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /api/threads/1/", "GET /api/threads/1/"]
--- more_headers eval
["XF-Api-Key: client-a", "XF-Api-Key: client-b"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 4: a GET carrying _xfToken bypasses -- the CSRF token is per-session
# _xfToken is XF's CSRF token as a query arg (logout link, style-variation
# switcher). Its value is per-session, so any GET carrying it is per-user and
# must never be cached or served across visitors. Arg rules are path-independent,
# so the /xf/ prefix exercises them.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /xf/thread-tok?_xfToken=1650000000,abcdef",
 "GET /xf/thread-tok?_xfToken=1650000000,abcdef"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 5: xf_user (remember-me) bypasses
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: xf_user=1234%2Cabcdef
--- request eval
["GET /xf/thread-a", "GET /xf/thread-a"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 6: xf_session_admin bypasses
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: xf_session_admin=deadbeef
--- request eval
["GET /xf/thread-admin", "GET /xf/thread-admin"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 7: xf_session bypasses -- THE LEAK GUARD
# xf_session is the ONLY cookie an ordinary (non-remember-me) login carries.
# Caching it serves an authenticated member's page to strangers. This assertion
# is inverted from the original preset on purpose. Do not "optimise" it out.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: xf_session=membersess123
--- request eval
["GET /xf/thread-sess", "GET /xf/thread-sess"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 8: xf_lscxf_logged_in bypasses
# The LiteSpeed plugin's true login-only cookie, present only if that plugin runs.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: xf_lscxf_logged_in=1
--- request eval
["GET /xf/thread-ls", "GET /xf/thread-ls"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 9: a cookieless guest still caches
# This is what stops the xf_session rule from being a blanket hit-rate zero:
# XF's session is LAZY, so a clean first-time visitor who stores nothing in it
# is issued no cookie at all. Without this arm, a bypass-everything bug passes
# every assertion above.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /xf/thread-b", "GET /xf/thread-b"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 10: xf_style_variation is VALUE-KEYED, and each value hits its own entry
# Presentation variants are tier-3 key_cookies: not bypassed and not
# presence-keyed. Each is a SHARED variant -- everyone on dark theme sees the
# same page -- so it must cache, repeat-hit its OWN entry, and NOT collide with
# a different value.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /xf/variant-sv", "GET /xf/variant-sv", "GET /xf/variant-sv"]
--- more_headers eval
["Cookie: xf_style_variation=aaaa",
 "Cookie: xf_style_variation=aaaa",
 "Cookie: xf_style_variation=bbbb"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}, qq{X-Cache: }]
--- response_body_like eval
[qr/xf_style_variation=aaaa/, qr/xf_style_variation=aaaa/, qr/xf_style_variation=bbbb/]
--- error_code eval
[200, 200, 200]



=== TEST 11: xf_style_id is VALUE-KEYED, and each value hits its own entry
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /xf/variant-si", "GET /xf/variant-si", "GET /xf/variant-si"]
--- more_headers eval
["Cookie: xf_style_id=aaaa",
 "Cookie: xf_style_id=aaaa",
 "Cookie: xf_style_id=bbbb"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}, qq{X-Cache: }]
--- response_body_like eval
[qr/xf_style_id=aaaa/, qr/xf_style_id=aaaa/, qr/xf_style_id=bbbb/]
--- error_code eval
[200, 200, 200]



=== TEST 12: xf_language_id is VALUE-KEYED, and each value hits its own entry
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /xf/variant-li", "GET /xf/variant-li", "GET /xf/variant-li"]
--- more_headers eval
["Cookie: xf_language_id=aaaa",
 "Cookie: xf_language_id=aaaa",
 "Cookie: xf_language_id=bbbb"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}, qq{X-Cache: }]
--- response_body_like eval
[qr/xf_language_id=aaaa/, qr/xf_language_id=aaaa/, qr/xf_language_id=bbbb/]
--- error_code eval
[200, 200, 200]



=== TEST 13: EVERY declared key cookie is folded, not just the first present
# The preset declares xf_style_id, xf_style_variation and xf_language_id. If the
# key stopped at the first match, two requests agreeing on xf_style_id and
# differing on xf_language_id would share ONE entry -- a German reader served the
# English page, and the same cookie the operator asked to vary on silently
# ignored. Hold the earlier cookie fixed, vary only the later one.
#
# The X-Cache sequence alone does not prove separation: it shows request 3 was
# not a HIT, but not that it received its OWN body. ct_http_config()'s origin
# stamps a unique value per contact, so asserting that the =de body differs
# from the =en body is what actually rules out a shared entry.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /xf/multikey", "GET /xf/multikey", "GET /xf/multikey", "GET /xf/multikey"]
--- more_headers eval
["Cookie: xf_style_id=7; xf_language_id=en",
 "Cookie: xf_style_id=7; xf_language_id=en",
 "Cookie: xf_style_id=7; xf_language_id=de",
 "Cookie: xf_style_id=7; xf_language_id=de"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}, qq{X-Cache: }, qq{X-Cache: HIT}]
--- response_body_like eval
[qr/xf_language_id=en/, qr/xf_language_id=en/,
 qr/xf_language_id=de/, qr/xf_language_id=de/]
--- error_code eval
[200, 200, 200, 200]



=== TEST 14: varying only the EARLIER cookie must still split the key
# Symmetrical to TEST 13, so the fold cannot be reduced to "the last cookie wins".
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /xf/multikey2", "GET /xf/multikey2", "GET /xf/multikey2"]
--- more_headers eval
["Cookie: xf_style_id=7; xf_language_id=en",
 "Cookie: xf_style_id=7; xf_language_id=en",
 "Cookie: xf_style_id=9; xf_language_id=en"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}, qq{X-Cache: }]
--- response_body_like eval
[qr/xf_style_id=7/, qr/xf_style_id=7/, qr/xf_style_id=9/]
--- error_code eval
[200, 200, 200]



=== TEST 15: generic must NOT pull in the xenforo URI rules
# xenforo is opt-in and must NOT be folded into another preset: its URIs
# (/login, /register, /contact, /misc) are generic English words that a non-forum
# site can legitimately serve as cacheable pages.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /gen/login", "GET /gen/login"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 16: generic must NOT pull in the xenforo cookie rules
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: xf_user=1234%2Cabcdef
--- request eval
["GET /gen/page", "GET /gen/page"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
