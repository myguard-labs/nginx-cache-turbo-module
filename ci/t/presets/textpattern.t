# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Textpattern preset (docs/textpattern.md). Ported from test_textpattern_login_cookies()
# in ci/tools/test_runtime.py, which is deleted by this port.
#
# THE COOKIE RULE IS PRESENCE-ONLY, AND WHY
# ------------------------------------------------------------------------
# Verbatim from the ct_textpattern_cookies[] header comment in src, because it
# names why this preset does NOT need the per-request value predicate:
#
#   Both login cookies are written after every successful login; `txp_login_public`
#   is the frontend signal and `txp_login` protects the admin side. Anonymous public
#   requests do not receive either one.
#
# The rule is presence-only, same shape as phorum.t and punbb.t: guests never
# receive either cookie, so matching on the name alone is a safe, sufficient
# signal for a logged-in session. No value predicate needed.
#
# THE COOKIE NAMES -- BOTH SHARE A PREFIX
# ------------------------------------------------------------------------
# `txp_login_public=` and `txp_login=` are both matched via
# ngx_http_cache_turbo_cookie_has(), a plain SUBSTRING search over the raw
# Cookie header value -- not a name lookup, and not a suffix-of-name match
# (that stricter matcher belongs to the separate predicate tier, which this
# preset does not use). Both needles end in "=" so the substring match
# captures both the presence check (name must be present) AND a notational
# cue (the cookie must have a value being set, not a bare unset directive).
# TEST 5/6 cover each name independently; TEST 7 tests a dynamic prefix on
# the cookie name (a proxy-prefixed variant still bypasses, since the needle
# can match anywhere in the header).
#
# THE URI LIST -- SINGLE ENTRY, SEGMENT-TERMINATED
# ------------------------------------------------------------------------
# The admin folder defaults to /textpattern but can be renamed, so the guide
# requires an operator rule when it is moved. No arg rows (ct_textpattern_args[]
# is { NULL }), and the preset row carries NULL in cookie_preds and key_cookies,
# so this file has no arg leg, no predicate leg and no value-keying leg.
#
# "/textpattern" IS SLASH-LESS -- THE SEGMENT-TERMINATION BRANCH IS LIVE HERE
# Same shape as phorum.t's "/admin.php" and punbb.t's "/login.php": the byte
# after the needle must be '/' or '.' or end-of-URI. TEST 2 is the
# segment-termination oracle: "/textpatternZZ" continues with 'Z', neither a
# boundary byte nor EOF, so it must CACHE. TEST 3 covers the two positive
# boundary arms ("/textpattern/extra" and "/textpattern.bak") that DO bypass.
#
# THE VACUOUS URI TEST TRAP
# ------------------------------------------------------------------------
# uri_prefix() is byte-0 anchored, so a URI test served under a DIFFERENT
# location prefix (e.g. "/admin/textpattern") never reaches the rule at all and
# would pass with the row deleted. TEST 1 puts the URI arm at the ROOT path;
# TEST 12 is the explicit negative proving "/admin/textpattern" HITs precisely
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

# Root-anchored prefix locations: /textpattern for the URI row tests,
# /content/ for path-independent cookie cases (won't trigger URI bypass rule),
# /admin/ for the byte-0 vacuity control, /gen/ is the isolation control.
our $Config = ct_config(
    { path => '/textpattern',   backend => 'textpattern' },
    { path => '/content/',      backend => 'textpattern' },
    { path => '/admin/',        backend => 'textpattern' },
    { path => '/gen/',          backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: the URI row bypasses at the root, with no cookie
# The ct_textpattern_uris[] table entry, at the root path so a shared key cannot
# mask the bypass.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /textpattern", "GET /textpattern"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 2: SEGMENT BOUNDARY -- /textpatternZZ must CACHE
# "/textpattern" is slash-less, so the boundary branch of
# ngx_http_cache_turbo_uri_prefix() is LIVE. The byte after the needle here
# is 'Z', not '/' or '.' and not end-of-URI, so this is a different path
# segment that merely shares the prefix and must cache. Served under the
# real /textpattern location so the HIT cannot pass for free on an implicit
# 404.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /textpatternZZ", "GET /textpatternZZ"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 3: the two positive boundary arms still bypass
# "/textpattern/extra" ('/' continuation) and "/textpattern.bak" ('.'
# continuation) are both inside the matched subtree per the boundary check.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /textpattern/extra", "GET /textpattern/extra",
 "GET /textpattern.bak",   "GET /textpattern.bak"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 4: member LEAK GUARD -- /textpattern bypasses with NO cookie present
# The admin folder is a logged-in surface. Caching it serves one member's
# admin view to every later requester. The bypass is per-URI, not cookie-gated,
# so this is asserted with no Cookie header at all.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /textpattern", "GET /textpattern"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 5: txp_login_public= cookie bypasses
# Frontend login signal. Written after every successful login; anonymous public
# requests do not receive it.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: txp_login_public=abc123
--- request eval
["GET /content/read-a", "GET /content/read-a"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 6: txp_login= cookie bypasses
# Admin-side login signal. Written after every successful login; anonymous public
# requests do not receive it.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: txp_login=def456
--- request eval
["GET /content/read-b", "GET /content/read-b"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 7: txp_login under a proxy prefix still bypasses -- SUBSTRING match
# Both cookie names are matched by plain substring search over the raw
# Cookie header, so a proxy- or theme-prefixed variant still matches --
# the needle just needs to appear anywhere in the header.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: myapp_txp_login=ghi789
--- request eval
["GET /content/read-prefix", "GET /content/read-prefix"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 8: an EMPTY cookie value still bypasses -- presence, not NONEMPTY
# The rule is presence-only, so an empty value is still a bypass -- the
# fail-CLOSED direction.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: txp_login_public=
--- request eval
["GET /content/read-empty", "GET /content/read-empty"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 9: a bare valueless cookie (no '=') does NOT bypass
# The needle is "txp_login_public=" (includes the '='), so a bare cookie
# name "txp_login_public" without a '=' does NOT contain that substring and
# does NOT bypass. The request must cache because there is no bypass signal.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: txp_login_public
--- request eval
["GET /content/read-bare", "GET /content/read-bare"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 10: an unrelated guest cookie does NOT bypass
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: PHPSESSID=abc
--- request eval
["GET /content/read-guest", "GET /content/read-guest"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 11: txp_login_public bypasses when it is NOT the only cookie
# The bypass cookie must never end the cookie scan -- test a leading
# non-matching cookie followed by txp_login_public=.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: PHPSESSID=abc; txp_login_public=xyz
--- request eval
["GET /content/read-multi", "GET /content/read-multi"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 12: THE VACUOUS URI TEST -- /admin/textpattern HITs, not byte-0
# uri_prefix() is byte-0 anchored, so a URI test served under a location whose
# path is NOT the root never reaches the rule. This proves a URI arm sent under
# /admin/ would pass for free even with the row deleted -- which is exactly why
# the URI arm in TEST 1 is sent at the true root instead.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /admin/textpattern", "GET /admin/textpattern"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 13: the textpattern cookie under /gen/ (wordpress backend) still HITs
# Isolation control. wordpress has its own cookie list and the textpattern
# rows do not leak across backends.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: txp_login_public=abc123
--- request eval
["GET /gen/topic-iso", "GET /gen/topic-iso"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
