# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# YaBB preset (docs/yabb.md). Ported from test_yabb_preset() in
# ci/tools/test_runtime.py, which is deleted in the same commit.
#
# THE PRESET IS ARG-AND-COOKIE ONLY
# ---------------------------------
# `ct_yabb_uris[] = { NULL }`. YaBB is a single-script CGI app -- every page is
# YaBB.pl?action=<route> -- so the whole dynamic surface lives in query args,
# not URI prefixes. There is consequently no URI test in this file and no
# segment-termination case; adding one would assert the engine, not the preset.
# The preset row also carries NULL in the cookie_preds and key_cookies slots, so
# those legs do not apply either. Same shape as smf (ci/t/presets/smf.t).
#
# WHY LOGOUT IS THE ROW THIS FILE EXISTS FOR
# -------------------------------------------
# Verbatim from the ct_yabb_args[] header comment in src, because it names the
# shipped leak:
#
#   `action=logout` is in the args list for the same reason `action=login` is,
#   and it is the more dangerous of the pair to omit: a cached logout response
#   is served without the request ever reaching LogInOut.pl, so the
#   UpdateCookie("delete") that terminates the session never runs and the member
#   stays logged in while being told they are not.
#
# The cookie-triple arm is NOT a substitute for it: a request carrying Y2User-*
# bypasses on the cookie rule alone and would pass with the args row still
# missing. TESTS 1-4 are therefore deliberately COOKIE-LESS.
#
# WHY THE COOKIE NAMES ARE SUBSTRINGS
# ------------------------------------
# YaBB appends a random per-install numeric suffix to each of Y2User-, Y2Pass-
# and Y2Sess-, so the wire name is unpredictable and only a SUBSTRING rule can
# match it. An operator who changes the naming convention breaks this preset
# silently -- the src comment documents that rather than coding around what
# cannot be discovered from the request. The tests below use a NON-STOCK suffix
# so an exact-name matcher would fail here.
#
# See ci/t/presets/xenforo.t for why every bypass case is fetched TWICE (a
# bypass and a first-time MISS both come back with no X-Cache, so a single fetch
# would pass with the rule removed) and why these are `--- request eval` arrays
# rather than `--- pipelined_requests`.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

# Arg rules and cookie rules are both path-independent, and the preset has no
# URI rows, so ONE prefixed location carries every yabb case. /gen/ is the
# isolation control -- a DIFFERENT preset, proving the yabb rows are opt-in and
# do not leak into another backend's location.
our $Config = ct_config(
    { path => '/yabb/', backend => 'yabb'      },
    { path => '/gen/',  backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: action=logout bypasses on the ARG rule alone, with NO cookie
# THE ROW THIS FILE EXISTS FOR. A cached logout response never reaches
# LogInOut.pl, so UpdateCookie("delete") never runs and the member stays logged
# in while being shown a logged-out page. Deliberately cookie-less: with a
# Y2User-* cookie present this would bypass on the COOKIE rule and pass with the
# args row missing entirely.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /yabb/YaBB.pl?action=logout", "GET /yabb/YaBB.pl?action=logout"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 2: the FIRST and LAST rows of ct_yabb_args[] both bypass
# action=post is row 1, action=imsend2 is the last row. A scan that stopped
# early -- or one that only ever checked a prefix of the table -- would still
# pass TEST 1 while leaving the tail of the table dead. Each is on its own path
# because the key is $request_uri only up to the query: two bypass cases sharing
# a path would both be uncacheable-by-key rather than uncacheable-by-rule.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /yabb/a1.pl?action=post",    "GET /yabb/a1.pl?action=post",
 "GET /yabb/a2.pl?action=imsend2", "GET /yabb/a2.pl?action=imsend2"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 3: the login, admin and PM rows bypass -- cookie-less
# The member-facing and privileged surfaces. These are the rows whose failure
# LEAKS: an admin panel or a member's PM inbox stored under a shared anonymous
# key and handed to strangers.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /yabb/b1.pl?action=login",    "GET /yabb/b1.pl?action=login",
 "GET /yabb/b2.pl?action=admin",    "GET /yabb/b2.pl?action=admin",
 "GET /yabb/b3.pl?action=pm",       "GET /yabb/b3.pl?action=pm",
 "GET /yabb/b4.pl?action=register", "GET /yabb/b4.pl?action=register"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200]



=== TEST 4: ';' is a YaBB query separator and the action is rarely first
# YaBB writes multi-argument URLs with ';' rather than '&', and the argument it
# dispatches on is usually NOT the first one -- the exact form the arg scanner
# was added for. A scanner that only split on '&', or only inspected the first
# argument, would leave every real-world logout link cacheable.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /yabb/YaBB.pl?num=17;action=logout",
 "GET /yabb/YaBB.pl?num=17;action=logout"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 5: an unrelated action= VALUE still caches -- the negative half
# THE LOAD-BEARING NEGATIVE. YaBB routes ordinary thread reads through the same
# `action` argument name as the dynamic routes, so a rule that matched the bare
# NAME "action" would bypass the entire board and silently switch the cache off.
# The rows are `name=value` and the VALUE is what must match. A plain thread
# read carrying no action at all must cache too.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /yabb/c1.pl?action=recent",  "GET /yabb/c1.pl?action=recent",
 "GET /yabb/c2.pl?num=17;start=15", "GET /yabb/c2.pl?num=17;start=15"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]



=== TEST 6: a row value must not match as a mere PREFIX of a longer value
# `action=post` and `action=post2` are BOTH rows, but `action=postfoo` is not.
# If the arg matcher compared only the row's length, an arbitrary unlisted route
# beginning with a listed one would bypass -- a hit-rate loss that widens every
# time a row is added. Requesting an unlisted extension of a listed value pins
# the comparison as whole-value.
#
# post2 gets its own positive arm rather than riding on the post row above.
# `action=post2` starts with the whole of `action=post`, so if the post2 row were
# deleted the negative below would STILL pass -- postfoo is unlisted either way.
# Only an explicit post2 bypass fails when its row goes.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /yabb/d1.pl?action=postfoo", "GET /yabb/d1.pl?action=postfoo",
 "GET /yabb/d2.pl?action=post2",   "GET /yabb/d2.pl?action=post2"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 7: a member carrying Y2User-<rand> MUST bypass -- THE LEAK GUARD
# The reason the cookie rows exist. Without them the member's authenticated
# board view is stored under the anonymous key and served to strangers. The
# numeric suffix is a NON-STOCK one: an exact-name matcher fails here.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: Y2User-91827=alice; Y2Sess-91827=deadbeef
--- request eval
["GET /yabb/YaBB.pl?num=17", "GET /yabb/YaBB.pl?num=17"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 8: ALL THREE of the Y2* rows bypass, each one ALONE
# ct_yabb_cookies[] lists Y2User-, Y2Pass- and Y2Sess-. Sending the triple
# together (TEST 7) would stay green with two of the three literals deleted --
# any one match ends the scan. Each cookie therefore gets its own request on its
# own path. The random suffix differs per row so no single literal can carry
# more than its own arm.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /yabb/e1", "GET /yabb/e1",
 "GET /yabb/e2", "GET /yabb/e2",
 "GET /yabb/e3", "GET /yabb/e3"]
--- more_headers eval
["Cookie: Y2User-91827=alice", "Cookie: Y2User-91827=alice",
 "Cookie: Y2Pass-40513=hash",  "Cookie: Y2Pass-40513=hash",
 "Cookie: Y2Sess-77104=sid",   "Cookie: Y2Sess-77104=sid"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 9: the cookie name is matched as a SUBSTRING, not byte-0 anchored
# THE STEP-4 ENGINE ORACLE for this file. ngx_http_cache_turbo_cookie_has()
# searches the whole Cookie header with ngx_strnstr, so a rule literal need not
# start at byte 0 of a cookie name. That is load-bearing for YaBB because the
# suffix is random and an operator may prepend a board prefix. Narrowing the
# match to an anchored ngx_strncmp turns exactly this arm red.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: myboardY2User-91827=alice
--- request eval
["GET /yabb/topic-sub", "GET /yabb/topic-sub"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 10: an EMPTY Y2User- value STILL bypasses -- presence, not NONEMPTY
# yabb carries NO cookie_preds row, so the rule is presence-only and an empty
# value is still a bypass. That is the fail-CLOSED direction: a member whose
# cookie was cleared mid-request must not be assumed a guest. Do not "fix" this
# into a NONEMPTY predicate.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: Y2User-91827=
--- request eval
["GET /yabb/topic-empty", "GET /yabb/topic-empty"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 11: a valueless bare `Y2User-91827` (no '=') bypasses
# There is no value to test and guessing "guest" would cache a possible member.
# An unreadable cookie must never be assumed to be a guest.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: Y2User-91827
--- request eval
["GET /yabb/topic-bare", "GET /yabb/topic-bare"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 12: an unrelated YaBB cookie does NOT bypass
# YaBB writes presentation and session cookies to plain guests too. If the rule
# matched those, essentially all traffic would bypass and the cache would be
# off. Only the Y2* identity names are bypass triggers.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: YaBBSettings=dark; PHPSESSID=deadbeef
--- request eval
["GET /yabb/topic-guest", "GET /yabb/topic-guest"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 13: nothing is keyed on a cookie -- YaBB declares no key_cookies
# The preset row carries NULL in the key_cookies slot. Two requests differing
# ONLY in a presentation cookie must therefore share ONE entry: request 2 HITs
# the entry request 1 stored, and its body still echoes request 1's cookie.
# Asserting the HIT alone would be satisfied by any accidental sharing; the body
# check pins that it is entry #1 specifically.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /yabb/nokey", "GET /yabb/nokey"]
--- more_headers eval
["Cookie: YaBBSettings=aaaa", "Cookie: YaBBSettings=bbbb"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- response_body_like eval
[qr/YaBBSettings=aaaa/, qr/YaBBSettings=aaaa/]
--- error_code eval
[200, 200]



=== TEST 14: the yabb rows are ISOLATED to a yabb location
# The rows are opt-in per backend, not global. Under the wordpress preset both a
# yabb arg row and a Y2User- identity cookie are ordinary cacheable traffic. If
# either bypassed here, the preset table would be leaking across backends and
# every one of the assertions above would be measuring the engine rather than
# the yabb rows.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /gen/f1.pl?action=logout", "GET /gen/f1.pl?action=logout",
 "GET /gen/f2.pl",               "GET /gen/f2.pl"]
--- more_headers eval
["", "",
 "Cookie: Y2User-91827=alice", "Cookie: Y2User-91827=alice"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]
