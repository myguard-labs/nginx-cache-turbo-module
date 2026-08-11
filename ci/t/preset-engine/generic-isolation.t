# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Preset ENGINE test: a NAMED preset must pull in ONLY its own rules, never
# another opt-in preset's URI or cookie rows. Ported from
# test_new_presets_not_in_generic() in ci/tools/test_runtime.py, which is
# DELETED by this port.
#
# This is a cross-cutting engine test, not a preset test: it lives in
# ci/t/preset-engine/, not ci/t/presets/. It rides on the wordpress preset
# only as the vehicle for proving preset ISOLATION -- wordpress's own row
# coverage stays in ci/t/presets/wordpress.t.
#
# THE INVARIANT
# --------------
# The opt-in presets' URI rules are ordinary English words and paths that an
# UNRELATED site legitimately serves as cacheable content: /login, /user,
# /admin, /session, /posts, /index.php are all real pages on plenty of
# sites that are not the forum/CMS the preset targets. Their cookie rules are
# just as generic-looking (_t=, a userID cookie). A `wordpress` location must
# therefore cache /user, /admin, /session and /index.php -- xenforo's,
# mybb's and vbulletin's own URI rules, respectively -- and must ignore
# xenforo's `_t` and mybb's `mywikiUserID`-style cookies, because none of
# those are wordpress's rules.
#
# This is not a historical accident: a `generic`/`auto` backend used to exist
# as the UNION of every preset's rules, and this exact test caught it pulling
# in another preset's surface. The union backend is gone (see
# test_auto_and_generic_are_removed), but the invariant it violated --
# "a named preset's rule set is exactly its own, nothing else's" -- still has
# to hold for every individual preset, which is what this file pins.
#
# Every case below fetches its URI/cookie TWICE via `--- request eval`
# arrays: the FIRST hit must MISS (X-Cache absent) and the SECOND must HIT
# (X-Cache: HIT). A single fetch cannot distinguish "correctly cacheable" from
# "accidentally bypassed" -- both come back with no X-Cache on their only
# request. Only the paired MISS-then-HIT proves the page is actually stored.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

our $Config = ct_config(
    { path => '/gen/', backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: /user is xenforo's URI rule -- wordpress must still cache it
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /gen/user", "GET /gen/user"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 2: /admin is mybb's URI rule -- wordpress must still cache it
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /gen/admin", "GET /gen/admin"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 3: /session is vbulletin's URI rule -- wordpress must still cache it
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /gen/session", "GET /gen/session"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 4: /index.php is smf's route -- wordpress must still cache it
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /gen/index.php", "GET /gen/index.php"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 5: an xenforo-shaped _t cookie must not bypass under wordpress
# Distinct URI per cookie case: the key is $uri, so reusing one path would let
# the second cookie HIT on the first cookie's entry and pass for free.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /gen/page-0", "GET /gen/page-0"]
--- more_headers eval
["Cookie: _t=abc123", "Cookie: _t=abc123"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 6: a mediawiki-shaped userID cookie must not bypass under wordpress
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /gen/page-1", "GET /gen/page-1"]
--- more_headers eval
["Cookie: mywikiUserID=42", "Cookie: mywikiUserID=42"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
