# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# P3-7 -- zone-wide background-refresh concurrency cap
#
# Per-key single-flight (ctn->refreshing) caps regens for ONE key; nothing
# capped the SUM of background-refresh (SWR bg-update) subrequests across
# every key sharing a zone. cache_turbo_background_update_max adds that cap
# via a zone-wide atomic (z->sh->bg_inflight), gated in warm_one() -- the one
# chokepoint every background-refresh subrequest goes through, whether fired
# by the SWR dice-winner (access.c) or the admin warm endpoint (admin.c).
#
# The admin warm endpoint (`POST /_cache?url=/a,/b`) is the test vehicle
# because it fires N warm_one() calls in one synchronous loop, all posted as
# NGX_HTTP_SUBREQUEST_BACKGROUND before any of them can run -- so the cap
# check races nothing: with background_update_max 1 and two URLs in one POST,
# the second call MUST see bg_inflight already at the cap and decline,
# deterministically, with no timing dependency. warmed=1 in the JSON reply
# (module.c counts a URL only when warm_one() returns NGX_OK) is therefore a
# direct, non-flaky proof that the gate fired -- not an inference from
# elapsed time or retries.
#
# TEST 1: default (unlimited, no directive) -- both URLs fire. Negative
#         control: proves nothing about the OTHER tests is coincidentally
#         capping warms (e.g. WARM_MAX, which is 32 and irrelevant here).
# TEST 2: background_update_max 1, two URLs in one POST -- only the first
#         fires (warmed=1). Isolates the cap: identical request to TEST 1,
#         opposite outcome, because only the cap directive differs.
# TEST 3: leak scenario. background_update_max 1 +
#         cache_turbo_test_warm_ctx_fail on -- warm_one()'s ctx-alloc arm
#         (module.c, right after ngx_http_subrequest() posts the subrequest)
#         is forced to fail and return NGX_ERROR on EVERY call. A
#         return-value-keyed decrement would never run (the caller only sees
#         NGX_ERROR, never a completion) and would leak the counter forever,
#         permanently wedging every future background refresh in the zone.
#         The pool-cleanup decrement (armed on sr->pool, not r->pool, right
#         after the subrequest is posted) must still fire when sr->pool is
#         freed. Proof: fire one warm (forced to fail -> warmed=0), wait for
#         the doomed subrequest to finish and free its pool, then poll
#         /_cache and assert bg_inflight is back to 0 -- not stuck at 1.
# TEST 4: same leak scenario, but SEVERAL forced-fail warms in a row (well
#         past background_update_max 1) -- if the decrement were leaking,
#         bg_inflight would climb monotonically and every later warm would
#         starve permanently once the leaked count reaches the cap. Proves
#         the zone is NOT wedged after repeated failures, which the earlier
#         hazard warns is exactly what a return-value-based decrement would
#         do.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

# One caching location per test group (warm targets) plus one admin location
# per group sharing that group's zone-equivalent config. All locations share
# the SAME `main` zone (ct_http_config's cache_turbo_zone main 16m;), so
# bg_inflight is genuinely shared across every path below -- exactly the
# cross-key surface the cap is meant to bound.
our $Config = ct_config(
    { path => '/unlimited/a', backend => 'wordpress' },
    { path => '/unlimited/b', backend => 'wordpress' },
) . <<'EOC';
        location = /_cache_unlimited {
            cache_turbo_admin main;
        }
EOC

run_tests();

__DATA__

=== TEST 1: default (no cap directive) -- both warms fire
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request
POST /_cache_unlimited?url=/unlimited/a,/unlimited/b
--- response_body_like: \{"warmed":2\}
--- error_code: 200



=== TEST 2: cache_turbo_background_update_max 1 -- second warm in the same POST is refused
--- http_config eval: $::HttpConfig
--- config eval
    CacheTurbo::ct_config(
        { path => '/capped/a', backend => 'wordpress',
          extra => 'cache_turbo_background_update_max 1;' },
        { path => '/capped/b', backend => 'wordpress',
          extra => 'cache_turbo_background_update_max 1;' },
    ) . <<'EOC'
        location = /_cache_capped {
            cache_turbo_admin main;
            cache_turbo_background_update_max 1;
        }
EOC
--- request
POST /_cache_capped?url=/capped/a,/capped/b
--- response_body_like: \{"warmed":1\}
--- error_code: 200



=== TEST 3: leak scenario -- a forced warm_one() ctx-alloc failure must not wedge bg_inflight
--- http_config eval: $::HttpConfig
--- config eval
    CacheTurbo::ct_config(
        { path => '/leak/a', backend => 'wordpress',
          extra => 'cache_turbo_background_update_max 1;'
                 . 'cache_turbo_test_warm_ctx_fail on;' },
    ) . <<'EOC'
        location = /_cache_leak {
            cache_turbo_admin main;
            cache_turbo_background_update_max 1;
            cache_turbo_test_warm_ctx_fail on;
        }
EOC
--- request eval
["POST /_cache_leak?url=/leak/a", "GET /_cache_leak"]
--- wait: 1
--- response_body_like eval
[qq{\\{"warmed":0\\}}, qr/"bg_inflight":0[,}]/]
--- error_code eval
[200, 200]



=== TEST 4: leak scenario, repeated -- several forced failures in a row must not wedge the zone
--- http_config eval: $::HttpConfig
--- config eval
    CacheTurbo::ct_config(
        { path => '/leak2/a', backend => 'wordpress',
          extra => 'cache_turbo_background_update_max 1;'
                 . 'cache_turbo_test_warm_ctx_fail on;' },
    ) . <<'EOC'
        location = /_cache_leak2 {
            cache_turbo_admin main;
            cache_turbo_background_update_max 1;
            cache_turbo_test_warm_ctx_fail on;
        }
EOC
--- request eval
["POST /_cache_leak2?url=/leak2/a", "POST /_cache_leak2?url=/leak2/a", "POST /_cache_leak2?url=/leak2/a", "GET /_cache_leak2"]
--- wait: 1
--- response_body_like eval
[qq{\\{"warmed":0\\}}, qq{\\{"warmed":0\\}}, qq{\\{"warmed":0\\}}, qr/"bg_inflight":0[,}]/]
--- error_code eval
[200, 200, 200, 200]
