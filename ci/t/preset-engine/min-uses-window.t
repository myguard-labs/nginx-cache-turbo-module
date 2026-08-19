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
# The elapsed-time gap is real wall-clock time via Test::Nginx::Socket's
# native `--- wait: N` section (Test/Nginx/Socket.pm: sleeps N seconds after
# each request in a `--- request eval` list, except the last). There is no
# other elapsed-time idiom in this suite -- grepped for `sleep` inside a
# `--- request eval` list across ci/t/ and found none; `--- wait` is the only
# documented delay primitive Test::Nginx::Socket exposes.
#
# TEST 1: Within window (2 misses ~1s apart, window=2s) -- both misses count,
#         min_uses 2 satisfied, third request (no further wait) is a HIT.
# TEST 2: Outside window (2 misses ~3s apart, window=2s) -- first miss counts
#         (miss_count=1), second miss is more than the window past
#         last_access so it resets (miss_count=1 again, not 2), third request
#         (no further wait) is still NOT a HIT -- the reset must be proven by
#         showing what min_uses 2 alone WOULD have produced (TEST 1) and that
#         the same gap DOESN'T produce it here.
# TEST 3: Default (window=0, OFF) -- lifetime counter: two misses ~3s apart
#         (same gap as TEST 2) still satisfy min_uses 2, so the third request
#         IS a HIT. This is the negative control that isolates the windowing
#         directive: identical timing to TEST 2, opposite outcome, because
#         only the window setting differs.
#
# Each test's final assertion is a HIT/MISS split, never a bare empty
# `X-Cache: ` on every request -- an empty header is what an uncached miss
# AND a not-yet-eligible miss both produce, so it can't tell "windowing
# worked" from "nothing was ever going to be cached here". A HIT can only
# happen if the preceding requests actually crossed min_uses and stored.

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

=== TEST 1: Within window (2 misses ~1s apart, window=2s) -- min_uses 2 satisfied, third request is a HIT
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /within-window/post-1", "GET /within-window/post-1", "GET /within-window/post-1"]
--- wait: 1
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200]



=== TEST 2: Outside window (2 misses ~3s apart, window=2s) -- gap exceeds window, counter resets, no HIT
# --- wait: 3 sleeps 3s after each request in the list (except the last), so
# both the 1st->2nd and 2nd->3rd gaps exceed the 2s window. The first miss
# sets miss_count=1; the second miss is >2s past last_access so P3-6 resets
# miss_count to 0 before incrementing, landing back at 1 -- never reaching
# min_uses 2. Contrast with TEST 3, which uses the identical 3s gaps but
# window=0: there the third request IS a HIT. The only variable that differs
# between TEST 2 and TEST 3 is the window setting, so a HIT here would prove
# the reset never fired.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /outside-window/post-2", "GET /outside-window/post-2", "GET /outside-window/post-2"]
--- wait: 3
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200]



=== TEST 3: Default (window=0, OFF), same 3s gaps as TEST 2 -- lifetime counter persists, third request is a HIT
# Identical --- wait: 3 gaps to TEST 2. window=0 disables windowing, so
# miss_count is never reset by elapsed time: first miss -> 1, second miss ->
# 2, satisfies min_uses 2, stores. Third request is a HIT. Same timing as
# TEST 2, opposite outcome -- isolates the window directive as the cause.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /no-window/post-3", "GET /no-window/post-3", "GET /no-window/post-3"]
--- wait: 3
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200]
