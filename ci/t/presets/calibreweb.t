# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Calibre-Web preset (docs/calibreweb.md). Cookies `session` (Flask) and
# `remember_token` (Flask-Login) plus the private URI areas. Guest HTML is only
# safe to cache with anonymous browsing on and no reverse-proxy header login.
#
# Negative control: with the preset removed every bypass TEST goes red.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

our $Config = ct_config(
    { path => '/login', backend => 'calibreweb' },
    { path => '/logout', backend => 'calibreweb' },
    { path => '/admin', backend => 'calibreweb' },
    { path => '/me', backend => 'calibreweb' },
    { path => '/download/', backend => 'calibreweb' },
    { path => '/show/', backend => 'calibreweb' },
    { path => '/send/', backend => 'calibreweb' },
    { path => '/ajax/', backend => 'calibreweb' },
    { path => '/read/', backend => 'calibreweb' },
    { path => '/kobo/', backend => 'calibreweb' },
    { path => '/kobo_auth/', backend => 'calibreweb' },
    { path => '/remote/login', backend => 'calibreweb' },
    { path => '/verify/', backend => 'calibreweb' },
    { path => '/cw/', backend => 'calibreweb' },
    { path => '/cover/', backend => 'calibreweb' },
    { path => '/alias/', backend => 'calibre-web' },
    { path => '/gen/', backend => 'wordpress' },
);

run_tests();

__DATA__


=== TEST 1: every URI row bypasses at the root, with no cookie
# The full ct_calibreweb_uris[] table, each on its own root path.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /login", "GET /login",
 "GET /logout", "GET /logout",
 "GET /admin", "GET /admin",
 "GET /me", "GET /me",
 "GET /download/1", "GET /download/1",
 "GET /show/1", "GET /show/1",
 "GET /send/1", "GET /send/1",
 "GET /ajax/1", "GET /ajax/1",
 "GET /read/1", "GET /read/1",
 "GET /kobo/1", "GET /kobo/1",
 "GET /kobo_auth/1", "GET /kobo_auth/1",
 "GET /remote/login", "GET /remote/login",
 "GET /verify/1", "GET /verify/1"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200,
 200, 200,
 200, 200,
 200, 200,
 200, 200,
 200, 200,
 200, 200,
 200, 200,
 200, 200,
 200, 200,
 200, 200,
 200, 200,
 200, 200]


=== TEST 2: SEGMENT BOUNDARY -- /adminXtra caches
# "/admin" is slash-less: the boundary branch is live. /adminXtra is another segment.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /adminXtra", "GET /adminXtra",
 "GET /admin/config", "GET /admin/config"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200,
 200, 200]


=== TEST 3: the Flask `session` cookie bypasses
# Login (and guest search) set it; fails safe for guests.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: session=eyJ.abc
--- request eval
["GET /cw/book/1", "GET /cw/book/1"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]


=== TEST 4: the `remember_token` cookie bypasses
# Flask-Login remember cookie.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: remember_token=abc|def
--- request eval
["GET /cw/book/2", "GET /cw/book/2"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]


=== TEST 5: a COOKIE_PREFIX-ed session cookie still bypasses (substring)
# COOKIE_PREFIX=cw_ gives cw_session; `session=` is a substring of it.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: cw_session=abc
--- request eval
["GET /cw/book/3", "GET /cw/book/3"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]


=== TEST 6: an unrelated cookie does NOT bypass
# Positive control.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: theme=dark
--- request eval
["GET /cw/book/guest", "GET /cw/book/guest"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]


=== TEST 7: covers and the guest library HIT
# Positive control: the preset does not bypass /cover/ or guest pages. The
# fixture origin marks both public; real Calibre-Web covers carry no-cache and
# need a cache_turbo_cache_control ignore location (docs/calibreweb.md).
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /cover/12/thumb", "GET /cover/12/thumb",
 "GET /cw/", "GET /cw/"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200,
 200, 200]


=== TEST 8: THE VACUOUS URI TEST -- /cw/admin HITs, not byte-0
# URI rows are byte-0 anchored.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /cw/admin", "GET /cw/admin"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]


=== TEST 9: the calibre-web alias arms the same preset
# Hyphenated alias maps to the same bit.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: session=a
--- request eval
["GET /alias/page", "GET /alias/page"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]


=== TEST 10: isolation -- session= under /gen/ (wordpress) still HITs
# Calibreweb rows do not leak.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: session=a
--- request eval
["GET /gen/topic-iso", "GET /gen/topic-iso"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
