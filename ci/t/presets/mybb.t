# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# MyBB preset (docs/mybb.md). Ported from test_mybb_preset() in
# ci/tools/test_runtime.py.
#
# URI + arg rules, the NONEMPTY cookie predicate on the SUFFIX "user", and the
# two key cookies that are matched EXACTLY. This file is where the engine's
# exact-vs-suffix asymmetry is pinned, so read that first.
#
# WHY THE PREDICATE IS A SUFFIX AND THE KEY IS NOT
# ------------------------------------------------
# `<cookieprefix>user` is written ONLY in the login success path
# (inc/datahandlers/login.php via member.php do_login) -- a guest structurally
# cannot receive it, so presence of a non-empty value is sufficient and no value
# predicate is needed. The prefix is an operator ACP setting and undiscoverable
# from the request, so the rule matches the SUFFIX "user" (phpBB's "_u"
# technique). A predicate can afford a loose match because its failure direction
# is a needless bypass: `coppauser`, a real MyBB cookie, also ends in "user" and
# costs a registrant's hit rate -- nothing worse.
#
# The KEY cookies (mybbtheme, mybblang) deliberately do NOT get that treatment.
# A key's loose match hands out BUCKET SELECTION: any client could fold a cookie
# of its own choosing (`evilmybbtheme=dark`) into the key, landing on the same
# bucket a real `mybbtheme=dark` reader uses, while the origin -- which ignores
# the unknown name -- returns the DEFAULT theme to be stored there. Exact
# matching instead fails as a hit-QUALITY bug on a prefixed board (nothing folds,
# every guest shares one bucket), which is the better of the two failures. The
# remedy is operator-side and already exists: `cache_turbo_key_cookie
# <prefix>mybbtheme <prefix>mybblang;` folds with identical framing.
#
# TEST 10/11 assert the loose-key attack does NOT work, and are the reason this
# file exists rather than being folded into a generic preset template. Do not
# "fix" them by making key cookies suffix-matched. That is the vulnerability.
#
# `sid` is issued to EVERY visitor including guests and bots and is deliberately
# NOT a bypass cookie -- the xf_session/SMFCookie trap. TEST 9 guards that.
#
# See ci/t/presets/xenforo.t for why every bypass case is fetched TWICE and why
# these are `--- request eval` arrays rather than `--- pipelined_requests`.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

# The preset's URI rules are prefixes anchored at byte 0, so /member.php,
# /usercp.php and /admin/ must be ROOT locations. /mybb/ carries the cookie and
# arg cases, which are path-independent. /gen/ is the isolation control -- a
# DIFFERENT preset, proving the mybb rows are opt-in and do not leak into
# another backend's location.
our $Config = ct_config(
    { path => '/member.php', backend => 'mybb'      },
    { path => '/usercp.php', backend => 'mybb'      },
    { path => '/admin/',     backend => 'mybb'      },
    { path => '/mybb/',      backend => 'mybb'      },
    { path => '/gen/',       backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: /member.php bypasses on the URI rule
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /member.php", "GET /member.php"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 2: /usercp.php bypasses on the URI rule
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /usercp.php", "GET /usercp.php"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 3: /admin/ bypasses -- the ACP, matched as a directory prefix
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /admin/index.php", "GET /admin/index.php"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 4: action=login bypasses on the ARG rule
# MyBB dispatches through action= rather than distinct URIs for these, so the
# auth surfaces are matched as query args, not paths.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /mybb/index.php?action=login", "GET /mybb/index.php?action=login"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 5: action=do_register and action=resetpassword bypass
# Two more rows of ct_mybb_args[], including the last one -- a scan that stopped
# early would still pass TEST 4.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /mybb/index.php?action=do_register", "GET /mybb/index.php?action=do_register",
 "GET /mybb/index.php?action=resetpassword", "GET /mybb/index.php?action=resetpassword"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 6: an unrelated action= value still caches
# The negative half of TEST 4/5. If the arg rule matched "action=" alone, every
# MyBB page would bypass and the cache would be off board-wide.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /mybb/index.php?action=lastpost", "GET /mybb/index.php?action=lastpost"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 7: a logged-in member (mybbuser non-empty) MUST bypass -- THE LEAK GUARD
# The cookie is written only on login success. Without this rule the member's
# authenticated page is stored and served to strangers.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: mybbuser=12_abcdef; sid=deadbeef
--- request eval
["GET /mybb/showthread-a", "GET /mybb/showthread-a"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 8: the cookie NAME is matched by SUFFIX -- member under any prefix
# `cookieprefix` is an ACP setting and undiscoverable from the request. A
# literal-name rule silently stops firing on a prefixed board, and a bypass rule
# that stops firing LEAKS.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /mybb/st-plain",  "GET /mybb/st-plain",
 "GET /mybb/st-pref",   "GET /mybb/st-pref",
 "GET /mybb/st-zz",     "GET /mybb/st-zz"]
--- more_headers eval
["Cookie: mybbuser=12_abc",        "Cookie: mybbuser=12_abc",
 "Cookie: myboard_mybbuser=12_abc", "Cookie: myboard_mybbuser=12_abc",
 "Cookie: zzuser=12_abc",          "Cookie: zzuser=12_abc"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 9: `sid` alone stays cacheable -- it is issued to guests and bots
# The xf_session/SMFCookie trap. Bypassing on the session cookie would bypass
# essentially all traffic and silently disable the cache.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: sid=deadbeef; mybb[lastvisit]=1700000000
--- request eval
["GET /mybb/showthread-b", "GET /mybb/showthread-b"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 10: an EMPTY mybbuser value is NOT a member -- NONEMPTY, not presence
# MyBB clears the cookie on logout by writing an empty value. Bypassing on
# presence alone would keep a logged-out visitor out of the cache forever.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: mybbuser=; sid=deadbeef
--- request eval
["GET /mybb/showthread-c", "GET /mybb/showthread-c"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 11: a valueless bare `mybbuser` (no '=') fails CLOSED to bypass
# There is no value to test, and guessing "guest" would cache a possible member.
# An unreadable cookie must never be assumed to be a guest.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: mybbuser; sid=deadbeef
--- request eval
["GET /mybb/showthread-d", "GET /mybb/showthread-d"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 12: mybbtheme is VALUE-KEYED, and each value hits its own entry
# Presentation variants are tier-3 key_cookies: not bypassed and not
# presence-keyed. Each is a SHARED variant -- everyone on dark theme sees the
# same page -- so it must cache, repeat-hit its OWN entry, and NOT collide with
# a different value.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /mybb/variant-theme", "GET /mybb/variant-theme", "GET /mybb/variant-theme"]
--- more_headers eval
["Cookie: mybbtheme=aaaa",
 "Cookie: mybbtheme=aaaa",
 "Cookie: mybbtheme=bbbb"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}, qq{X-Cache: }]
--- response_body_like eval
[qr/mybbtheme=aaaa/, qr/mybbtheme=aaaa/, qr/mybbtheme=bbbb/]
--- error_code eval
[200, 200, 200]



=== TEST 13: EVERY declared key cookie is folded, not just the first present
# The preset declares mybbtheme AND mybblang. If the key stopped at the first
# match, two requests agreeing on mybbtheme and differing on mybblang would share
# ONE entry -- a German reader served the English page, and the second cookie the
# operator asked to vary on silently ignored. Hold the earlier one fixed, vary
# only the later one.
#
# The X-Cache sequence alone does not prove separation: it shows request 3 was
# not a HIT, but not that it received its OWN body. ct_http_config()'s origin
# echoes the request Cookie, so asserting the =de body differs from the =en body
# is what actually rules out a shared entry.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /mybb/multikey", "GET /mybb/multikey", "GET /mybb/multikey", "GET /mybb/multikey"]
--- more_headers eval
["Cookie: mybbtheme=7; mybblang=en",
 "Cookie: mybbtheme=7; mybblang=en",
 "Cookie: mybbtheme=7; mybblang=de",
 "Cookie: mybbtheme=7; mybblang=de"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}, qq{X-Cache: }, qq{X-Cache: HIT}]
--- response_body_like eval
[qr/mybblang=en/, qr/mybblang=en/, qr/mybblang=de/, qr/mybblang=de/]
--- error_code eval
[200, 200, 200, 200]



=== TEST 14: a key cookie name is matched EXACTLY -- a prefixed one folds NOTHING
# THE DELIBERATE ASYMMETRY. The predicate above is a suffix match; the key is
# not. On a board with a cookieprefix the wire name is `<prefix>mybbtheme`, the
# exact match folds nothing, and both values land on ONE bucket: request 2 HITs
# the entry stored for request 1 even though its theme differs.
#
# This asserts a KNOWN, DOCUMENTED limitation, not a bug. It is the safe failure
# direction (hit quality, not bucket selection -- see TEST 15) and the operator
# remedy is `cache_turbo_key_cookie <prefix>mybbtheme;`.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /mybb/prefixed-key", "GET /mybb/prefixed-key"]
--- more_headers eval
["Cookie: myboard_mybbtheme=aaaa",
 "Cookie: myboard_mybbtheme=bbbb"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 15: an attacker cannot fold a cookie of its own choosing into the key
# THE SECURITY HALF of TEST 14, and the reason the key is not suffix-matched.
# If `evilmybbtheme` were accepted as a key cookie, request 2 would select the
# bucket a real `mybbtheme=dark` reader uses, while the origin -- which ignores
# the unknown name -- returns the DEFAULT page to be stored there, poisoning it.
#
# The assertion is POSITIVE, and that is what makes it strong: a request
# carrying only `evilmybbtheme` must key IDENTICALLY to one carrying no theme
# cookie at all, and therefore READ the entry a cookie-less request just warmed.
#
# Requests 1-2 warm the anonymous (no-cookie) entry. Request 3 carries only the
# lookalike and must HIT it -- proving the lookalike folded NOTHING. Merely
# asserting request 3 was not a HIT on some other entry would be satisfied by any
# unrelated miss; this pins which bucket it actually landed in.
#
# Requests 4-5 are the contrast: the GENUINE `mybbtheme` does fold, so it must
# NOT hit the anonymous entry, and gets its own body.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /mybb/evil-key", "GET /mybb/evil-key", "GET /mybb/evil-key",
 "GET /mybb/evil-key", "GET /mybb/evil-key"]
--- more_headers eval
["", "",
 "Cookie: evilmybbtheme=dark",
 "Cookie: mybbtheme=dark",
 "Cookie: mybbtheme=dark"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- response_body_like eval
[qr/ck=$/, qr/ck=$/, qr/ck=$/,
 qr/ck=mybbtheme=dark/, qr/ck=mybbtheme=dark/]
--- error_code eval
[200, 200, 200, 200, 200]



=== TEST 16: the mybb rows do not leak into another backend's location
# /gen/ runs the wordpress preset. The mybb URI, arg and cookie rules are opt-in
# per location; if the registry ORed every preset's rows together instead of
# selecting by bit, these would bypass here too.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /gen/index.php?action=login", "GET /gen/index.php?action=login"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 17: a mybb member cookie does not bypass under the wordpress preset
# The cookie half of TEST 16. `mybbuser` is not a wordpress signal, so the
# generic location must cache it -- proving the predicate is preset-scoped.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: mybbuser=12_abcdef
--- request eval
["GET /gen/showthread", "GET /gen/showthread"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
