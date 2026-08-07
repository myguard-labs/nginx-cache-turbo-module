# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# vBulletin preset (docs/vbulletin.md). Ported from test_vbulletin_preset() in
# ci/tools/test_runtime.py.
#
# THREE predicates over one cookie header, and the only EQ row in the registry:
#
#   userid    NONEMPTY   set only on login, removed on logout
#   password  NONEMPTY   ditto (the hashed remember-me half)
#   imloggedin EQ "yes"  the signal production LiteSpeed vB configs key on
#
# This is the file that pins the EQ operator, so TEST 8/9 (the value must be
# exactly "yes", not merely present and not a prefix of it) are its whole point.
# NONEMPTY and EQ fail in OPPOSITE directions on an unexpected value -- NONEMPTY
# bypasses, EQ caches -- and only a per-op test tells them apart.
#
# `bb_sessionhash` is issued to guests too (session tracking for everyone) and is
# deliberately NOT a bypass cookie -- the xf_session/SMFCookie trap. TEST 10
# guards that; without it a presence matcher would bypass ~all traffic.
#
# The `bb_` prefix is admin-configurable (Cookie and HTTP Header Options), so the
# rules match the SUFFIX "userid"/"password", not a hardcoded "bb_" literal. A
# rare manual FULL rename still evades it -- a documented gap, same class as
# every other admin-configurable-name caveat in this registry.
#
# WHY THERE IS ONLY ONE KEY COOKIE
# --------------------------------
# `bb_language` only. `bb_lastvisit` and `bb_lastactivity` are presentation
# cookies too, but they are per-visit TIMESTAMPS that change on essentially every
# request. Keying on them gave each visitor a private bucket the next request
# already invalidated -- a hit rate near zero on a board that otherwise caches
# well -- and, because the values come straight from the client, a free remote
# memory attack: anyone could mint unlimited distinct keys and push the zone into
# eviction. TEST 13 is the regression guard: a varying timestamp must NOT split
# the entry.
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

# The preset's URI rules are prefixes anchored at byte 0, so /login.php,
# /private.php and /admincp/ must be ROOT locations. /vb/ carries the cookie
# cases, which are path-independent. /gen/ is the isolation control -- a
# DIFFERENT preset, proving the vbulletin rows are opt-in.
our $Config = ct_config(
    { path => '/login.php',   backend => 'vbulletin' },
    { path => '/private.php', backend => 'vbulletin' },
    { path => '/admincp/',    backend => 'vbulletin' },
    { path => '/vb/',         backend => 'vbulletin' },
    { path => '/gen/',        backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: /login.php bypasses on the URI rule
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /login.php", "GET /login.php"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 2: /private.php bypasses -- private messages
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /private.php", "GET /private.php"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 3: /admincp/ bypasses -- the control panel, a directory prefix
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /admincp/index.php", "GET /admincp/index.php"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 4: an ordinary forum page caches
# The baseline. vBulletin declares NO arg rules (ct_vbulletin_args[] is empty),
# so a query string alone must never bypass -- unlike mybb's action= rows.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /vb/showthread.php?t=5", "GET /vb/showthread.php?t=5"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 5: bb_userid (NONEMPTY) MUST bypass -- THE LEAK GUARD
# Set only on login, removed on logout, never issued to a guest. Without this
# rule the member's authenticated page is stored and served to strangers.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: bb_sessionhash=abc; bb_userid=42
--- request eval
["GET /vb/showthread-a", "GET /vb/showthread-a"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 6: bb_password (NONEMPTY) MUST bypass -- the second predicate row
# A scan that stopped after the first predicate would still pass TEST 5.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: bb_sessionhash=abc; bb_password=deadbeefdeadbeef
--- request eval
["GET /vb/showthread-b", "GET /vb/showthread-b"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 7: an EMPTY userid/password is NOT a member -- NONEMPTY, not presence
# vBulletin clears these on logout by writing an empty value. Bypassing on
# presence alone would keep every logged-out visitor out of the cache.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /vb/logged-out-a", "GET /vb/logged-out-a",
 "GET /vb/logged-out-b", "GET /vb/logged-out-b"]
--- more_headers eval
["Cookie: bb_userid=; bb_sessionhash=abc",   "Cookie: bb_userid=; bb_sessionhash=abc",
 "Cookie: bb_password=; bb_sessionhash=abc", "Cookie: bb_password=; bb_sessionhash=abc"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]



=== TEST 8: bbimloggedin=yes bypasses -- the EQ predicate matching
# The only EQ row in the registry. Some builds signal login with this instead of
# bb_userid, and production LiteSpeed vB caching configs key on it.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: bbimloggedin=yes
--- request eval
["GET /vb/imlogged-a", "GET /vb/imlogged-a"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 9: EQ compares the WHOLE value -- "no", "yes2" and "ye" all cache
# THE OPERATOR TEST. EQ is exact and length-checked, not a prefix and not a
# presence check:
#   "no"    -- the literal logged-out value; a presence matcher would bypass it
#   "yesX"  -- longer; a prefix compare (strncmp without the length guard) would
#              wrongly bypass, so this pins vlen == cmplen
#   "ye"    -- shorter, a prefix OF the literal; the other direction of the same
#              length guard
# Getting any of these wrong is silent: the board simply stops caching for a
# slice of visitors, or leaks for another.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /vb/eq-no",    "GET /vb/eq-no",
 "GET /vb/eq-long",  "GET /vb/eq-long",
 "GET /vb/eq-short", "GET /vb/eq-short"]
--- more_headers eval
["Cookie: bbimloggedin=no",   "Cookie: bbimloggedin=no",
 "Cookie: bbimloggedin=yes2", "Cookie: bbimloggedin=yes2",
 "Cookie: bbimloggedin=ye",   "Cookie: bbimloggedin=ye"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 9b: a matching cookie BEHIND a non-matching one must still bypass
# THE SCAN-TERMINATION REGRESSION, both arms. One browser visiting two boards on
# the same host sends two cookies whose names both end in the suffix. A "this
# pair says cacheable" answer must NOT end the scan -- whichever came first would
# otherwise decide for the whole request, and a leading logged-out value would
# mask a logged-in one behind it, caching and serving that member's page.
#
#   NONEMPTY: an EMPTY `bb_userid=` first, a populated `other_userid=42` behind
#   EQ:       a non-literal `bb_imloggedin=no` first, an `other_imloggedin=yes`
#             behind
#
# Both must bypass. This is the same defect phpBB's TEST 12 guards for the NE
# arm -- see ci/t/presets/phpbb.t.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /vb/twin-nonempty", "GET /vb/twin-nonempty",
 "GET /vb/twin-eq",       "GET /vb/twin-eq"]
--- more_headers eval
["Cookie: bb_userid=; other_userid=42",         "Cookie: bb_userid=; other_userid=42",
 "Cookie: bb_imloggedin=no; other_imloggedin=yes",
 "Cookie: bb_imloggedin=no; other_imloggedin=yes"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 10: bb_sessionhash alone stays cacheable -- guests get one too
# The xf_session trap. Session tracking is issued to EVERY visitor, so a
# presence matcher here identifies nobody and disables the cache board-wide.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: bb_sessionhash=abcdef; bb_lastvisit=1700000000
--- request eval
["GET /vb/guest-a", "GET /vb/guest-a"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 11: the cookie NAME is matched by SUFFIX -- member under any prefix
# The `bb_` prefix is an admin setting (Cookie and HTTP Header Options). A
# literal-name rule silently stops firing on a renamed board, and a bypass rule
# that stops firing LEAKS.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /vb/sfx-bb",   "GET /vb/sfx-bb",
 "GET /vb/sfx-my",   "GET /vb/sfx-my",
 "GET /vb/sfx-zz",   "GET /vb/sfx-zz"]
--- more_headers eval
["Cookie: bb_userid=42",       "Cookie: bb_userid=42",
 "Cookie: myboard_userid=42",  "Cookie: myboard_userid=42",
 "Cookie: zzpassword=beef",    "Cookie: zzpassword=beef"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 12: bb_language is VALUE-KEYED, and each value hits its own entry
# The one key cookie. A SHARED variant -- everyone reading in German sees the
# same page -- so it must cache, repeat-hit its OWN entry, and not collide with
# a different value. The body echo proves separation; the X-Cache sequence alone
# would only show request 3 was not a HIT, not that it got its own body.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /vb/variant-lang", "GET /vb/variant-lang", "GET /vb/variant-lang"]
--- more_headers eval
["Cookie: bb_language=en",
 "Cookie: bb_language=en",
 "Cookie: bb_language=de"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}, qq{X-Cache: }]
--- response_body_like eval
[qr/bb_language=en/, qr/bb_language=en/, qr/bb_language=de/]
--- error_code eval
[200, 200, 200]



=== TEST 13: bb_lastvisit is NOT keyed -- a per-request timestamp must not split
# THE REGRESSION GUARD. bb_lastvisit/bb_lastactivity change on essentially every
# request. Keying on them gave each visitor a private bucket the next request
# already invalidated (hit rate near zero), and since the value is client-supplied
# it was also a free remote memory attack -- mint unlimited keys, push the zone
# into eviction.
#
# Two requests differing ONLY in the timestamp must share ONE entry.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /vb/nokey-ts", "GET /vb/nokey-ts"]
--- more_headers eval
["Cookie: bb_language=en; bb_lastvisit=1700000000",
 "Cookie: bb_language=en; bb_lastvisit=1799999999"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 14: a key cookie name is matched EXACTLY -- no client-chosen folding
# The security half of the exact-match rule (see ci/t/presets/mybb.t). If a
# suffix matched here, `evilbb_language` would select the bucket a real
# `bb_language=de` reader uses while the origin returns the default page to be
# stored there.
#
# The assertion is POSITIVE: a request carrying only `evilbb_language` must key
# IDENTICALLY to one carrying no language cookie, and READ the entry a
# cookie-less request warmed (requests 1-3). The genuine cookie does fold, so it
# must miss that entry and get its own (requests 4-5).
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /vb/evil-key", "GET /vb/evil-key", "GET /vb/evil-key",
 "GET /vb/evil-key", "GET /vb/evil-key"]
--- more_headers eval
["", "",
 "Cookie: evilbb_language=de",
 "Cookie: bb_language=de",
 "Cookie: bb_language=de"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- response_body_like eval
[qr/ck=$/, qr/ck=$/, qr/ck=$/,
 qr/ck=bb_language=de/, qr/ck=bb_language=de/]
--- error_code eval
[200, 200, 200, 200, 200]



=== TEST 15: the vbulletin rows do not leak into another backend's location
# /gen/ runs the wordpress preset. bb_userid is not a wordpress signal, so the
# generic location must cache it -- proving the predicates are preset-scoped and
# the registry selects by bit rather than ORing every preset's rows together.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: bb_userid=42; bbimloggedin=yes
--- request eval
["GET /gen/showthread", "GET /gen/showthread"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
