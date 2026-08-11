# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Preset ENGINE test: the query-arg scanner must percent-decode, split on
# ';', and look past the FIRST occurrence of a name. Ported from
# test_preset_arg_scanner() in ci/tools/test_runtime.py, which is DELETED by
# this port.
#
# This is a cross-cutting engine test, not a preset test: it lives in
# ci/t/preset-engine/, not ci/t/presets/. It rides on the smf, xenforo and
# discourse presets only as vehicles for the scanner behaviour common to all
# of them -- each preset's own row coverage stays in its own ci/t/presets/
# file.
#
# THE THREE BUGS, ALL FAIL-OPEN WITH CORE NGINX'S ngx_http_arg()
# ----------------------------------------------------------------
#   * ngx_http_arg splits only on '&'. SMF and YaBB build nearly every
#     multi-argument URL with ';' ("?u=42;action=login"), so everything
#     after the first argument was invisible and those presets' arg rows
#     matched nothing on a real board URL.
#   * ngx_http_arg does not percent-decode. PHP routes
#     "%61ction=log%69n" exactly like "action=login", so an encoded login
#     URL was cached.
#   * ngx_http_arg returns the FIRST occurrence and stops. PHP's $_GET
#     keeps the LAST, so a harmless value prefixed onto the real one
#     ("?action=display&action=login") hid the dynamic route.
#
# See ci/t/presets/xenforo.t for why every bypass case below is fetched
# TWICE via `--- request eval` arrays: a bypass and a first-time MISS both
# come back with no X-Cache header, so a single fetch would pass with the
# scanner removed entirely. Only a bypass keeps the header absent on the
# SECOND request -- an ordinary MISS would have been stored and would
# answer HIT.
#
# The /smf/ location keys on $request_uri (query string included), matching
# ci/tools/test_runtime.py's fixture: with the default $uri-only key, every
# query variant on /smf/index.php would collapse onto ONE cache entry and
# the per-case assertions would stop meaning anything. /xf/ and /dc/ do not
# need this override -- each of their cases already lives on its own URI
# path, not merely its own query string.
#
# PHP's KEY MANGLING (the xenforo/discourse arms)
# ------------------------------------------------
# php_register_variable_ex() rewrites '.' and ' ' to '_' when it builds a
# $_GET key, so "?.xfToken=" reaches XenForo as "_xfToken" -- the exact
# argument name the preset bypasses on -- and a percent-decoding-only
# matcher misses every alias. A literal '+' is a space in form encoding and
# mangles the same way. The fold is applied to EVERY preset, not only the
# PHP ones: Discourse runs on Rack, which does not mangle, so on Discourse
# the fold can only ever cost an unnecessary bypass -- the safe direction --
# and the discourse arms below pin that uniform behaviour rather than a
# Discourse-specific one.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

our $Config = ct_config(
    { path => '/smf/', backend => 'smf',
      extra => 'cache_turbo_key $request_uri;' },
    { path => '/xf/',  backend => 'xenforo'   },
    { path => '/dc/',  backend => 'discourse' },
);

run_tests();

__DATA__

=== TEST 1: ';' is a query separator for SMF/YaBB-style URLs
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /smf/index.php?u=42;action=login&n=0", "GET /smf/index.php?u=42;action=login&n=0"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 2: the argument NAME may be percent-encoded
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /smf/index.php?%61ction=login&n=1", "GET /smf/index.php?%61ction=login&n=1"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 3: the argument VALUE may be percent-encoded
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /smf/index.php?action=log%69n&n=2", "GET /smf/index.php?action=log%69n&n=2"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 4: a LATER occurrence of a repeated argument name still counts
# ngx_http_arg returns the FIRST occurrence; PHP's $_GET keeps the LAST. A
# harmless value prefixed onto the real one must not hide the dynamic route.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /smf/index.php?action=display&action=login&n=3", "GET /smf/index.php?action=display&action=login&n=3"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 5: the match may be the LAST of several ';'-separated arguments
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /smf/index.php?board=1;u=42;action=pm&n=4", "GET /smf/index.php?board=1;u=42;action=pm&n=4"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 6: the negative half -- decoding and ';'-splitting must not turn an ordinary read route into a bypass
# If the scanner over-matches, the board has simply been un-cached.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /smf/index.php?u=42;action=display",  "GET /smf/index.php?u=42;action=display",
 "GET /smf/index.php?action=%64isplay",     "GET /smf/index.php?action=%64isplay",
 "GET /smf/index.php?actionx=login",        "GET /smf/index.php?actionx=login"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 7: PHP's key mangling -- '.' , ' ' and a literal '+' in an argument NAME fold to '_' and still match
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /xf/thread-mangle?%2ExfToken=1650000000,abcdef",
 "GET /xf/thread-mangle?%2ExfToken=1650000000,abcdef",
 "GET /xf/thread-mangle2?+xfToken=1650000000,abcdef",
 "GET /xf/thread-mangle2?+xfToken=1650000000,abcdef",
 "GET /dc/topic-mangle?api%2Ekey=deadbeef",
 "GET /dc/topic-mangle?api%2Ekey=deadbeef",
 "GET /dc/topic-mangle2?api%20username=admin",
 "GET /dc/topic-mangle2?api%20username=admin"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200]



=== TEST 8: the mangling fold is a NAME rule only -- an unrelated name that merely contains a fold character must not suddenly match
# Or every preset with an underscore in an arg row starts bypassing traffic
# it has no business seeing.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /xf/thread-nomangle?x.xfToken=1", "GET /xf/thread-nomangle?x.xfToken=1",
 "GET /dc/topic-nomangle?api.keyx=1",   "GET /dc/topic-nomangle?api.keyx=1"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]
