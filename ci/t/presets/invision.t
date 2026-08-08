# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Invision Community (IPS4) preset (docs/invision.md). Ported from
# test_invision_preset() in ci/tools/test_runtime.py.
#
# The NONEMPTY predicate on the SUFFIX `_loggedIn`, front-controller URI rules,
# `do=`/`module=` ARG rules, and THREE key cookies -- the longest key list in
# this batch, which is what makes TEST 13 (every declared key cookie is folded,
# not just the first present) worth having here.
#
# IPS NAMES THE CACHING COOKIE FOR YOU. Unlike XenForo -- where stock XF2 has no
# login-only cookie and the preset must bypass on the session (see
# ci/t/presets/xenforo.t) -- IPS sets `ips4_loggedIn` on login and only on
# login, so a NONEMPTY predicate is exact and costs no guest hit rate.
#
# `ips4_IPSSessionFront` is issued to EVERY visitor, guests included (ordinary
# session tracking), and is deliberately NOT a bypass cookie -- the
# xf_session/SMFCookie shape. TEST 9 guards it.
#
# The `ips4_` prefix is admin-configurable (Overriding Default Cookie Options),
# so the predicate matches the SUFFIX `_loggedIn`, the same prefix-agnostic
# technique phpBB's `_u` and Drupal's `SESS` use.
#
# WHY do= IS AN ARG RULE AND NOT A URI RULE
# -----------------------------------------
# IPS routes through `app=core&module=...&do=...` controller dispatch rather than
# one stable posting URI, so posting/messaging/moderation surfaces cannot be
# matched as paths. They are matched as query args, alongside the fixed
# front-controller paths (/login, /register, /lostpassword, /messenger, /admin).
#
# WHY ips4_device_key IS NOT A KEY COOKIE
# ---------------------------------------
# It is the counter-example that defines the rule. The key cookies here are
# cosmetic (theme, language, JS detection) -- shared by everyone who picked the
# same value, never an identity signal. `ips4_device_key` is a PER-DEVICE
# fingerprint: keying on it gives every visitor a private entry nobody else can
# hit, and because the value comes straight from the client it also lets one
# attacker mint unlimited distinct keys and push the zone into eviction. It
# carries no variant information either -- IPS sets it on the login POST for the
# remember-me device list, so its bearer is a MEMBER, already bypassed by
# _loggedIn. TEST 14 is the regression guard. (It is httpOnly, which is
# irrelevant here: httpOnly only hides a cookie from browser script; it is still
# sent in the Cookie header and this module sees it like any other.)
#
# See ci/t/presets/xenforo.t for why every bypass case is fetched TWICE and why
# these are `--- request eval` arrays rather than `--- pipelined_requests`.
# See ci/t/presets/mybb.t for the exact-vs-suffix key/predicate asymmetry.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

# The preset's URI rules are prefixes anchored at byte 0, so /login, /register
# and /messenger must be ROOT locations. /ips/ carries the cookie and arg cases,
# which are path-independent. /gen/ is the isolation control -- a DIFFERENT
# preset, proving the invision rows are opt-in.
our $Config = ct_config(
    { path => '/login',     backend => 'invision'  },
    { path => '/register',  backend => 'invision'  },
    { path => '/messenger', backend => 'invision'  },
    { path => '/ips/',      backend => 'invision'  },
    { path => '/gen/',      backend => 'wordpress' },
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



=== TEST 2: /register bypasses on the URI rule
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /register", "GET /register"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 3: /messenger bypasses -- private messaging
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /messenger", "GET /messenger"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 4: the URI rules match whole SEGMENTS, not raw byte prefixes
# ct_invision_uris[] rows are prefix-anchored but segment-terminated: a
# slash-less needle like "/register" matches only when the next byte is '/' or
# '.' (or the URI ends there). So IPS's sub-routes under a front controller are
# covered by the same row --
#
#   /login/oauth      MATCH   ('/' boundary -- inside the subtree)
#   /register.php     MATCH   ('.' boundary -- an extension on the same route)
#
# -- while a merely-similar sibling path is NOT, which is the point:
#
#   /registercomplete NO      a different route that happens to share a prefix
#
# A raw strncmp would bypass that last one, and every other page whose name
# starts with a needle ("/loginless-faq"), costing hit rate for no safety gain.
# The bypass list must not be able to swallow unrelated URLs by accident.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /login/oauth",       "GET /login/oauth",
 "GET /register.php",      "GET /register.php",
 "GET /registercomplete",  "GET /registercomplete"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 5: do=compose bypasses on the ARG rule
# IPS dispatches through app=core&module=...&do=..., so posting and messaging
# surfaces have no stable URI to match -- they are query args.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /ips/index.php?app=core&do=compose", "GET /ips/index.php?app=core&do=compose"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 6: do=reply, do=report and module=messaging bypass
# Three more rows of ct_invision_args[], including the last one -- a scan that
# stopped early would still pass TEST 5. Each is a distinct arg position too:
# first, middle and only.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /ips/index.php?do=reply",                    "GET /ips/index.php?do=reply",
 "GET /ips/index.php?app=core&do=report&id=5",     "GET /ips/index.php?app=core&do=report&id=5",
 "GET /ips/index.php?module=messaging",            "GET /ips/index.php?module=messaging"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 7: an unrelated do= value still caches
# The negative half of TEST 5/6. If the arg rule matched "do=" alone, every IPS
# controller URL would bypass and the cache would be off site-wide.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /ips/index.php?app=forums&do=findComment", "GET /ips/index.php?app=forums&do=findComment"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 8: ips4_loggedIn (NONEMPTY) MUST bypass -- THE LEAK GUARD
# Set on login and only on login. Without this rule the member's authenticated
# page is stored and served to strangers.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: ips4_IPSSessionFront=abc; ips4_loggedIn=1
--- request eval
["GET /ips/topic-a", "GET /ips/topic-a"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 9: ips4_IPSSessionFront alone stays cacheable -- guests get one too
# The xf_session trap. Session tracking is issued to EVERY visitor, so a
# presence matcher on it identifies nobody and disables the cache site-wide.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: ips4_IPSSessionFront=abcdef; ips4_guestTime=1700000000
--- request eval
["GET /ips/topic-b", "GET /ips/topic-b"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 10: an EMPTY ips4_loggedIn is NOT a member -- NONEMPTY, not presence
# IPS clears the cookie on logout by writing an empty value. Bypassing on
# presence alone would keep every logged-out visitor out of the cache.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: ips4_loggedIn=; ips4_IPSSessionFront=abc
--- request eval
["GET /ips/topic-c", "GET /ips/topic-c"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 11: a valueless bare `ips4_loggedIn` (no '=') fails CLOSED to bypass
# There is no value to test, and guessing "guest" would cache a possible member.
# An unreadable cookie must never be assumed to be a guest.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: ips4_loggedIn; ips4_IPSSessionFront=abc
--- request eval
["GET /ips/topic-d", "GET /ips/topic-d"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 12: the cookie NAME is matched by SUFFIX -- member under any prefix
# The `ips4_` prefix is admin-configurable (Overriding Default Cookie Options).
# A literal-name rule silently stops firing on a renamed board, and a bypass
# rule that stops firing LEAKS.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /ips/sfx-std",  "GET /ips/sfx-std",
 "GET /ips/sfx-pref", "GET /ips/sfx-pref",
 "GET /ips/sfx-zz",   "GET /ips/sfx-zz"]
--- more_headers eval
["Cookie: ips4_loggedIn=1",        "Cookie: ips4_loggedIn=1",
 "Cookie: mysite_loggedIn=1",      "Cookie: mysite_loggedIn=1",
 "Cookie: zz_loggedIn=1",          "Cookie: zz_loggedIn=1"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 13: EVERY declared key cookie is folded, not just the first present
# The preset declares ips4_hasJS, ips4_theme AND ips4_language -- three, the
# longest list in this batch. If the key stopped at the first match, two requests
# agreeing on the earlier cookies and differing on ips4_language would share ONE
# entry: a German reader served the English page, and the cookie the operator
# asked to vary on silently ignored. Hold the earlier two fixed, vary only the
# last.
#
# The X-Cache sequence alone does not prove separation: it shows request 3 was
# not a HIT, but not that it received its OWN body. The origin echoes the request
# Cookie, so asserting the =de body differs from the =en body is what actually
# rules out a shared entry.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /ips/multikey", "GET /ips/multikey", "GET /ips/multikey", "GET /ips/multikey"]
--- more_headers eval
["Cookie: ips4_hasJS=true; ips4_theme=7; ips4_language=en",
 "Cookie: ips4_hasJS=true; ips4_theme=7; ips4_language=en",
 "Cookie: ips4_hasJS=true; ips4_theme=7; ips4_language=de",
 "Cookie: ips4_hasJS=true; ips4_theme=7; ips4_language=de"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}, qq{X-Cache: }, qq{X-Cache: HIT}]
--- response_body_like eval
[qr/ips4_language=en/, qr/ips4_language=en/, qr/ips4_language=de/, qr/ips4_language=de/]
--- error_code eval
[200, 200, 200, 200]



=== TEST 14: ips4_device_key is NOT keyed -- a per-device value must not split
# THE REGRESSION GUARD, and the counter-example that defines what a key cookie
# is. Keying on a per-device fingerprint gives every visitor a private entry
# nobody else can hit, and since the value is client-supplied it is a free remote
# memory attack: mint unlimited keys, push the zone into eviction.
#
# Two requests differing ONLY in ips4_device_key must share ONE entry.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /ips/nokey-dev", "GET /ips/nokey-dev"]
--- more_headers eval
["Cookie: ips4_theme=7; ips4_device_key=aaaaaaaaaaaa",
 "Cookie: ips4_theme=7; ips4_device_key=bbbbbbbbbbbb"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 15: ips4_theme is VALUE-KEYED, and each value hits its own entry
# A SHARED variant -- everyone on theme 7 sees the same page -- so it must cache,
# repeat-hit its OWN entry, and not collide with a different value. Paired with
# TEST 14 this pins the distinction: cosmetic-and-shared is keyed, per-device is
# not, and both live in the same Cookie header.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /ips/variant-theme", "GET /ips/variant-theme", "GET /ips/variant-theme"]
--- more_headers eval
["Cookie: ips4_theme=aaaa",
 "Cookie: ips4_theme=aaaa",
 "Cookie: ips4_theme=bbbb"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}, qq{X-Cache: }]
--- response_body_like eval
[qr/ips4_theme=aaaa/, qr/ips4_theme=aaaa/, qr/ips4_theme=bbbb/]
--- error_code eval
[200, 200, 200]



=== TEST 16: a key cookie name is matched EXACTLY -- no client-chosen folding
# The security half of the exact-match rule (see ci/t/presets/mybb.t). If a
# suffix matched here, `evilips4_theme` would select the bucket a real
# `ips4_theme=dark` reader uses while the origin returns the default page to be
# stored there.
#
# The assertion is POSITIVE: a request carrying only `evilips4_theme` must key
# IDENTICALLY to one carrying no theme cookie, and READ the entry a cookie-less
# request warmed (requests 1-3). The genuine cookie does fold, so it must miss
# that entry and get its own (requests 4-5).
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /ips/evil-key", "GET /ips/evil-key", "GET /ips/evil-key",
 "GET /ips/evil-key", "GET /ips/evil-key"]
--- more_headers eval
["", "",
 "Cookie: evilips4_theme=dark",
 "Cookie: ips4_theme=dark",
 "Cookie: ips4_theme=dark"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- response_body_like eval
[qr/ck=$/, qr/ck=$/, qr/ck=$/,
 qr/ck=ips4_theme=dark/, qr/ck=ips4_theme=dark/]
--- error_code eval
[200, 200, 200, 200, 200]



=== TEST 17: the invision rows do not leak into another backend's location
# /gen/ runs the wordpress preset. Neither the do= arg rules nor ips4_loggedIn
# are wordpress signals, so the generic location must cache both -- proving the
# registry selects rows by preset bit rather than ORing every preset together.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /gen/index.php?do=compose", "GET /gen/index.php?do=compose",
 "GET /gen/topic",                "GET /gen/topic"]
--- more_headers eval
["", "",
 "Cookie: ips4_loggedIn=1", "Cookie: ips4_loggedIn=1"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]
