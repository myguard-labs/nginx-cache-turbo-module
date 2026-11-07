# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# calibre content server preset (docs/calibre.md). URI tier only: the content
# server has no session cookie and no API key. With server auth ON requests carry
# an Authorization header and the storage floor never caches them, so the preset
# matters for the open (auth off, the default) case.
#
# Negative control: with the preset removed every bypass TEST goes red.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

our $Config = ct_config(
    { path => '/cdb/', backend => 'calibre' },
    { path => '/book-set-last-read-position', backend => 'calibre' },
    { path => '/book-set-annotations', backend => 'calibre' },
    { path => '/book-get-last-read-position', backend => 'calibre' },
    { path => '/book-get-annotations', backend => 'calibre' },
    { path => '/interface-data/init', backend => 'calibre' },
    { path => '/ajax-setup', backend => 'calibre' },
    { path => '/kosync/', backend => 'calibre' },
    { path => '/kosyncx', backend => 'calibre' },
    { path => '/book-get-storage', backend => 'calibre' },
    { path => '/book-get-storagex', backend => 'calibre' },
    { path => '/book-set-storage', backend => 'calibre' },
    { path => '/calibre/', backend => 'calibre' },
    { path => '/static/', backend => 'calibre' },
    { path => '/gen/', backend => 'wordpress' },
);

run_tests();

__DATA__


=== TEST 1: every URI row bypasses at the root
# The full ct_calibre_uris[] table. No cookie and no arg row exist: the content
# server has neither a session cookie nor an API key. The slash-less names are
# full route names; a /book-set- stem would match nothing (boundary rule).
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /cdb/cmd/list", "GET /cdb/cmd/list",
 "GET /book-set-last-read-position/x/1", "GET /book-set-last-read-position/x/1",
 "GET /book-set-annotations/x/1", "GET /book-set-annotations/x/1",
 "GET /book-get-last-read-position/x/1", "GET /book-get-last-read-position/x/1",
 "GET /book-get-annotations/x", "GET /book-get-annotations/x",
 "GET /interface-data/init", "GET /interface-data/init",
 "GET /ajax-setup", "GET /ajax-setup"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
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
 200, 200]


=== TEST 2: SEGMENT BOUNDARY -- /ajax-setupX caches, /ajax-setup.json bypasses
# "/ajax-setup" is slash-less: the boundary branch is live.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /ajax-setupX", "GET /ajax-setupX",
 "GET /ajax-setup.json", "GET /ajax-setup.json"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200,
 200, 200]


=== TEST 3: /interface-data/init (per-user ETag) bypasses
# The init endpoint's ETag includes the username.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /interface-data/init", "GET /interface-data/init"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]


=== TEST 4: /static/ assets and the library UI HIT
# Positive control: a calibre-server preset that bypasses everything would defeat the point.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /static/main.js", "GET /static/main.js",
 "GET /calibre/index.html", "GET /calibre/index.html"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200,
 200, 200]


=== TEST 5: THE VACUOUS URI TEST -- /calibre/cdb/x HITs, not byte-0
# URI rows are byte-0 anchored.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /calibre/cdb/x", "GET /calibre/cdb/x"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]


=== TEST 6: a cookie does not bypass (no cookie row)
# calibre-server has no session cookie; `session=` must not bypass here.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: session=abc
--- request eval
["GET /calibre/book/1", "GET /calibre/book/1"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]


=== TEST 7: isolation -- /gen/ (wordpress) is unaffected
# Calibre rows do not leak.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /gen/cdb/x", "GET /gen/cdb/x"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 8: KOReader sync and per-user storage rows bypass at the root
# /kosync/ serves per-user reading progress from X-Auth-User, not Authorization;
# /book-get-storage and /book-set-storage are per-user key/value stores.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /kosync/syncs/progress/abc", "GET /kosync/syncs/progress/abc",
 "GET /book-get-storage/lib/1/EPUB", "GET /book-get-storage/lib/1/EPUB",
 "GET /book-set-storage/lib/1/EPUB", "GET /book-set-storage/lib/1/EPUB"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 9: NEGATIVE -- /kosyncx and /book-get-storagex are different segments and cache
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /kosyncx", "GET /kosyncx",
 "GET /book-get-storagex", "GET /book-get-storagex"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]
