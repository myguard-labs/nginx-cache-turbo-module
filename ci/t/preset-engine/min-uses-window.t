# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# P3-6 -- windowed min_uses counter reset
#
# miss_count resets when now - last_access > window, so two misses
# separated by MORE than the window are treated as a fresh count (do NOT
# satisfy min_uses 2, no store), while two misses within the window DO
# satisfy min_uses 2 (store).
#
# TEST 1: Within window (2 misses < 2s apart) -- both satisfy min_uses 2, store
# TEST 2: Outside window (2 misses > 2s apart with window=2) -- first miss counts,
#         second miss resets counter, needs 2 fresh misses, so no store on second
# TEST 3: Default (window=0, OFF) -- lifetime counter, two misses always satisfy
#         min_uses 2 regardless of time gap
#
# Each test uses the MISS-then-HIT pattern to distinguish "correctly cached"
# from "never cached" -- a single fetch cannot tell them apart (both return
# no X-Cache header on their only request).

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

# Test 1 and 2: cache_turbo_min_uses 2 with window=2
# Test 3: cache_turbo_min_uses 2 with window=0 (OFF, default)
our $Config = ct_config(
    { path => '/within-window/', backend => 'wordpress',
      extra => 'cache_turbo_min_uses 2; cache_turbo_min_uses_window 2;' },
    { path => '/outside-window/', backend => 'wordpress',
      extra => 'cache_turbo_min_uses 2; cache_turbo_min_uses_window 2;' },
    { path => '/no-window/', backend => 'wordpress',
      extra => 'cache_turbo_min_uses 2;' },
);

run_tests();

__DATA__

=== TEST 1: Within window (2 misses < 2s apart) -- min_uses 2 satisfied, stored and re-served as HIT
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /within-window/post-1", "GET /within-window/post-1"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 2: Outside window (2 misses > 2s apart) -- first miss counts, second resets, no min_uses, no store, no HIT on second request
# The test sleeps 3 seconds between requests to exceed the 2s window.
# After sleep, last_access is 3s old, so miss_count resets to 0 when accessed.
# Single miss (count=1) does not satisfy min_uses 2, so second request goes
# to origin but is not stored. No HIT on third request.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /outside-window/post-2", "sleep 3; GET /outside-window/post-2", "GET /outside-window/post-2"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200]



=== TEST 3: Default (window=0, OFF) -- lifetime counter, two misses satisfy min_uses 2 regardless of time gap
# Same sleep as TEST 2 (3 seconds), but window=0 disables windowing.
# miss_count persists across the sleep, so both misses count toward min_uses 2.
# Second request stores, third request is a HIT.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /no-window/post-3", "sleep 3; GET /no-window/post-3", "GET /no-window/post-3"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200]
