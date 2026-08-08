# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# SMF (Simple Machines Forum) preset (docs/smf.md).
#
# SMF has NO dedicated test in ci/tools/test_runtime.py -- it appeared there
# only as the VEHICLE for two cross-cutting engine tests
# (test_preset_arg_value_predicate, test_preset_arg_scanner), which are not this
# preset's tests and stay in Python. This file is therefore a pure ADDITION: it
# is the first coverage of the smf ROWS themselves, and nothing is deleted.
#
# THE PRESET IS ARG-AND-COOKIE ONLY
# ---------------------------------
# `ct_smf_uris[] = { NULL }` -- there are no URI rows, deliberately. SMF routes
# every page through one entry script (index.php?action=<route>), so its whole
# dynamic surface is expressed as query-arg VALUES rather than paths. There is
# consequently no URI test in this file and no segment-termination case; adding
# one would assert the engine, not the preset. The preset row also carries NULL
# in the cookie_preds and key_cookies slots, so those legs do not apply either.
#
# WHY THE COOKIE RULE IS PRESENCE-ONLY DESPITE BEING GUEST-ISSUED
# ---------------------------------------------------------------
# Verbatim from the ct_smf_cookies[] header comment in src, because it names the
# tempting wrong repair:
#
#   SMFCookie (name is `$cookiename` from Settings.php, default "SMFCookie" +
#   version suffix e.g. SMFCookie20/21, so the rule matches the SUBSTRING
#   "SMFCookie" not a full literal) is issued to EVERY visitor, guests included
#   -- the phpBB shape exactly. loadUserSettings() in SMF's own core only treats
#   it as authenticated when the embedded password-hash element is non-empty; a
#   guest's value carries id_member=0 and an empty password field.
#
#   A general-purpose nginx cookie matcher cannot safely JSON/PHP-serialize
#   decode the structured value and validate hash shape, so the pragmatic proxy
#   (same class of compromise as phpBB's presence-of-suffix rule) is: bypass
#   whenever the cookie is present AT ALL. This is presence-only despite the
#   cookie being guest-issued, and it is NOT free -- it costs hit rate on guests
#   who have merely started a session. That is the accepted XenForo-style trade:
#   correct, not maximally fast. Do not "optimise" this into a value predicate
#   without actually parsing the cookie's array/JSON structure.
#
#   The 2FA companion cookie `<cookiename>_tfa` only exists mid-login and is
#   folded into the same presence rule for completeness.
#
# So unlike mybb/phpbb, an EMPTY `SMFCookie20=` value and a bare valueless
# `SMFCookie20` both still bypass -- presence-only fails CLOSED in both
# directions. TEST 9/10 pin that, and they are the OPPOSITE expectation from
# mybb.t's TEST 10/11. Do not "harmonise" them.
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
# URI rows, so ONE prefixed location carries every smf case. /gen/ is the
# isolation control -- a DIFFERENT preset, proving the smf rows are opt-in and
# do not leak into another backend's location.
our $Config = ct_config(
    { path => '/smf/', backend => 'smf'       },
    { path => '/gen/', backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: action=login bypasses on the ARG rule
# The first row of ct_smf_args[] that a real board serves anonymously.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /smf/index.php?action=login", "GET /smf/index.php?action=login"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 2: the FIRST and LAST rows of ct_smf_args[] both bypass
# action=admin is row 1, action=xmlhttp is the last row. A scan that stopped
# early -- or one that only ever checked a prefix of the table -- would still
# pass TEST 1 while leaving the tail of the table dead. Each is on its own path
# because cache_turbo_key is $uri: two bypass cases sharing a path would both be
# uncacheable-by-key rather than uncacheable-by-rule.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /smf/a1.php?action=admin",   "GET /smf/a1.php?action=admin",
 "GET /smf/a2.php?action=xmlhttp", "GET /smf/a2.php?action=xmlhttp"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 3: the write and moderation rows bypass -- profile, pm, post2, moderate
# The member-facing surfaces. These are the rows whose failure LEAKS: a member's
# own profile or PM inbox stored under a shared key and handed to strangers.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /smf/b1.php?action=profile",  "GET /smf/b1.php?action=profile",
 "GET /smf/b2.php?action=pm",       "GET /smf/b2.php?action=pm",
 "GET /smf/b3.php?action=post2",    "GET /smf/b3.php?action=post2",
 "GET /smf/b4.php?action=moderate", "GET /smf/b4.php?action=moderate"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200]



=== TEST 4: an unrelated action= VALUE still caches -- the negative half
# THE LOAD-BEARING NEGATIVE. SMF routes ordinary reads through the same `action`
# argument name as the dynamic routes, so a rule that matched the bare NAME
# "action" would bypass the entire board and silently switch the cache off. The
# rows are `name=value` and the VALUE is what must match.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /smf/c1.php?action=display", "GET /smf/c1.php?action=display",
 "GET /smf/c2.php?action=recent",  "GET /smf/c2.php?action=recent"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]



=== TEST 5: a row value must not match as a mere PREFIX of a longer value
# `action=login` is a row; `action=login2` is ALSO a row, but `action=loginfoo`
# is not. If the arg matcher compared only the row's length, an arbitrary
# unlisted route beginning with a listed one would bypass -- a hit-rate loss
# that widens every time a row is added. Requesting an unlisted extension of a
# listed value pins the comparison as whole-value.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /smf/d1.php?action=loginfoo", "GET /smf/d1.php?action=loginfoo"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 6: a member carrying SMFCookie MUST bypass -- THE LEAK GUARD
# The reason the cookie row exists. Without it the member's authenticated board
# view is stored under the anonymous key and served to strangers.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: SMFCookie20=a%3A4%3A%7Bi%3A0%3Bs%3A2%3A%2242%22%3B%7D
--- request eval
["GET /smf/topic-a", "GET /smf/topic-a"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 7: the cookie name is matched as a SUBSTRING -- every version suffix
# `$cookiename` in Settings.php defaults to "SMFCookie" with the schema version
# appended (SMFCookie20 on SMF 2.0, SMFCookie21 on 2.1), and the operator may
# change it outright. A full-literal rule stops firing on any board that is not
# the exact version the rule was written against, and a bypass rule that stops
# firing LEAKS. All three wire names below must bypass.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /smf/e1", "GET /smf/e1",
 "GET /smf/e2", "GET /smf/e2",
 "GET /smf/e3", "GET /smf/e3"]
--- more_headers eval
["Cookie: SMFCookie=x",       "Cookie: SMFCookie=x",
 "Cookie: SMFCookie20=x",     "Cookie: SMFCookie20=x",
 "Cookie: myboardSMFCookie=x", "Cookie: myboardSMFCookie=x"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 8: the 2FA companion `<cookiename>_tfa` bypasses too
# It exists only mid-login and is folded into the same presence rule. Named
# explicitly in the src header comment, so it gets an explicit assertion.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: SMFCookie20_tfa=deadbeef
--- request eval
["GET /smf/topic-tfa", "GET /smf/topic-tfa"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 9: an EMPTY SMFCookie value STILL bypasses -- presence, not NONEMPTY
# DELIBERATELY THE OPPOSITE of mybb.t TEST 10. smf carries no cookie_preds row;
# the rule is presence-only, so an empty value is still a bypass. That is the
# fail-CLOSED direction and it is the accepted cost documented in src: a guest
# who merely started a session loses their hit rate. Do not "fix" this into a
# NONEMPTY predicate -- SMF's guest value is a non-empty serialised array with
# an empty password field, so NONEMPTY would not separate guests from members
# anyway; it would only stop guarding logged-out-with-cleared-cookie.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: SMFCookie20=
--- request eval
["GET /smf/topic-empty", "GET /smf/topic-empty"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 10: a valueless bare `SMFCookie20` (no '=') bypasses
# There is no value to test and guessing "guest" would cache a possible member.
# An unreadable cookie must never be assumed to be a guest.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: SMFCookie20
--- request eval
["GET /smf/topic-bare", "GET /smf/topic-bare"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 11: an unrelated SMF cookie does NOT bypass
# The trap this preset's src comment names. SMF also writes PHPSESSID and a
# per-board `openid_url`-style companion to plain guests. If the rule matched
# those, essentially all traffic would bypass and the cache would be off. Only
# the identity cookie's name is a bypass trigger.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: PHPSESSID=deadbeef; smf_theme=2
--- request eval
["GET /smf/topic-guest", "GET /smf/topic-guest"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 12: nothing is keyed on a cookie -- SMF declares no key_cookies
# The preset row carries NULL in the key_cookies slot. Two requests differing
# ONLY in a presentation cookie must therefore share ONE entry: request 2 HITs
# the entry request 1 stored, and its body still echoes request 1's cookie.
# Asserting the HIT alone would be satisfied by any accidental sharing; the body
# check pins that it is entry #1 specifically.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /smf/nokey", "GET /smf/nokey"]
--- more_headers eval
["Cookie: smf_theme=aaaa", "Cookie: smf_theme=bbbb"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- response_body_like eval
[qr/smf_theme=aaaa/, qr/smf_theme=aaaa/]
--- error_code eval
[200, 200]



=== TEST 13: the smf rows are ISOLATED to an smf location
# The rows are opt-in per backend, not global. Under the wordpress preset both
# an smf arg row and the SMFCookie identity cookie are ordinary cacheable
# traffic. If either bypassed here, the preset table would be leaking across
# backends and every one of the assertions above would be measuring the engine
# rather than the smf rows.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /gen/f1.php?action=login", "GET /gen/f1.php?action=login",
 "GET /gen/f2.php",              "GET /gen/f2.php"]
--- more_headers eval
["", "",
 "Cookie: SMFCookie20=x", "Cookie: SMFCookie20=x"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]
