# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# P5-5r -- cache_turbo_breaker_count_retries.
#
# BACKGROUND: proxy_next_upstream runs UNDERNEATH this module. When an
# upstream group has some dead peers and some healthy ones, nginx retries
# across peers before this module's header filter ever runs, so the filter
# only ever sees the FINAL attempt's status -- a request that ultimately
# SUCCEEDED via retry looks identical, to the breaker, to a request that
# succeeded on the first try. A half-dead group (peers failing, retries
# landing on a healthy one) can therefore serve every client request 200 OK
# while the breaker's failure counter never moves, because it only ever
# hears about the ONE attempt that mattered.
#
# ngx_http_cache_turbo_breaker_retry_failures() (module.c) closes that gap
# by walking r->upstream_states -- nginx's own per-attempt array, one entry
# per peer tried, each already carrying its own status/header_time by the
# time headers are sent -- and counting every entry before the last one that
# looks like a failure (5xx, or header_time == -1 meaning "never got a
# header", the same transport-failure sentinel used elsewhere in this
# module). ngx_http_cache_turbo_header_filter_record_breaker() (filters.c)
# feeds each of those into the SAME ngx_http_cache_turbo_shm_breaker_record()
# call used for the final outcome, gated behind the new
# cache_turbo_breaker_count_retries flag.
#
# ⚠ SCOPE, discovered empirically while building this test: shm_breaker_record()
# (shm.c) unconditionally zeroes breaker_fails on ANY success, regardless of
# state -- "A success clears the failure run" is unconditional, not merely a
# CLOSED-state branch. That is correct, pre-existing, protected behaviour this
# item must not alter (the packet's own instruction). Its consequence: retry
# failures recorded for one request can only ever survive to trip the breaker
# WITHIN that same request's own record() calls, before that request's own
# final-outcome success call runs and clears them. They cannot accumulate
# ACROSS separate successful requests -- request N's trailing success always
# wipes what request N-1's retries added, one window-write later. So the
# achievable, correctly-scoped fix is: a SINGLE request whose own retry chain
# racks up >= threshold failed peer attempts before its final attempt succeeds
# now trips the breaker on THAT request, where before this change a request's
# retries were invisible to the breaker no matter how many peers it burned
# through. This is still the real gap from the task (retries are invisible),
# just resolved at the granularity record()'s own semantics allow: per
# request, not smeared across a longer trickle of separately-successful
# requests. TEST 2 below proves exactly this: ONE request against 3 dead
# peers + 1 alive, threshold=3, trips on its own retries; TEST 3 proves a
# SECOND, all-first-try-successful request right after does NOT stay tripped
# by residual accumulation from a different, later window -- each block's
# breaker state is a property of what its own requests actually did.
#
# DEFAULT-OFF: this changes WHEN a request's own retries can trip the
# breaker (a site that already free-rides on proxy_next_upstream retries
# today never trips the breaker on those, no matter how many peers a single
# request burns through), so it must not move any existing deployment's
# behaviour. Off is the default and reproduces today's final-status-only
# counting exactly -- TEST 1 proves this for the identical traffic pattern.
#
# ORACLE: X-Cache: BREAKER-503, the module's own header on the pre-origin
# 503 the OPEN breaker answers with (ngx_http_cache_turbo_breaker_unavailable
# in access.c) when nothing is armed to serve stale. A request landing on a
# TRIPPED breaker gets this header with no origin contact at all -- direct
# proof the breaker counted enough failures, not an inference from timing.
#
# THE UPSTREAM GROUP: THREE dead peers (nothing listening on any of their
# ports, so nginx gets ECONNREFUSED -- a genuine transport failure,
# connect_time/header_time both -1 -- for each) plus one healthy origin.
# `proxy_next_upstream error` (the default) and `proxy_next_upstream_tries 4`
# let a single request retry across all three dead peers before landing on
# the healthy one, so ONE request's own upstream_states array carries 3
# failed attempts before its final (successful) one -- enough by itself to
# reach breaker_threshold=3 in the flag-ON test.
#
# `server ... max_fails=0` on every peer: max_fails=0 disables nginx's OWN
# passive health check entirely, so a dead peer is retried on EVERY single
# request rather than being ejected after a few failures -- otherwise
# nginx's own next_upstream bookkeeping would eventually stop retrying a
# dead peer and this test would silently degrade into "the breaker sees an
# all-healthy group", proving nothing about the retry path.
#
# PORTS: fixed, in the 19420-19490 band reserved for this suite (avoids the
# dynamic-port collision hazard CacheTurbo.pm documents for shared origins,
# and this file needs several specific DEAD ports + a specific ALIVE port in
# the same upstream block, which ct_origin_port() does not support for a
# multi-peer group).
#
# SHARED-ZONE HAZARD: TEST 1 (flag off) and TEST 2/3 (flag on) each need
# their OWN cache_turbo_breaker zone with a FRESH failure counter --
# Test::Nginx reuses one nginx process across every `=== TEST` block that
# shares one `--- http_config`/`--- config` pair (Test::Nginx::Util's
# $should_restart), so if TEST 1 and TEST 2 shared one zone, TEST 1's failed
# attempts (recorded even with the flag off, via the ordinary per-request
# path once a request happens to land on a dead peer first) would carry
# into TEST 2's count. TEST 1 therefore gets its own `--- http_config`/
# `--- config` (distinct zone/upstream/location names), forcing Test::Nginx
# to restart nginx with a clean zone before TEST 2. TEST 2 and TEST 3 SHARE
# their zone deliberately -- proving the trip from TEST 2 does not fabricate
# extra evidence for TEST 3 requires them to run against the SAME zone/window,
# not a fresh one.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();

# Fixed, distinct per test group to avoid the SHARED-ZONE HAZARD above and to
# stay inside the reserved 19420-19490 band.
our $dead1  = 19420; # TEST 1: never listened on -> ECONNREFUSED
our $alive1 = 19421;
our $deadA  = 19430; # TEST 2/3: three dead peers, never listened on
our $deadB  = 19431;
our $deadC  = 19432;
our $aliveN = 19433;

run_tests();

__DATA__

=== TEST 1: flag OFF (default) -- a request that succeeds via retry never trips the breaker
--- http_config eval
qq{
    cache_turbo_zone off_zone 16m;

    upstream off_upstream {
        server 127.0.0.1:$::dead1 weight=3 max_fails=0;
        server 127.0.0.1:$::alive1 max_fails=0;
    }

    server {
        listen       127.0.0.1:$::alive1;
        server_name  alive_off;
        location / {
            add_header Cache-Control "no-store" always;
            return 200 "origin-alive-off\\n";
        }
    }
}
--- config eval
qq{
    location = /breakeroff/ {
        cache_turbo off_zone;
        cache_turbo_key \$uri\$request_id;
        cache_turbo_valid 1;
        cache_turbo_breaker on;
        cache_turbo_breaker_threshold 3;
        cache_turbo_breaker_window 30;
        cache_turbo_breaker_count_retries off;
        proxy_next_upstream error timeout;
        proxy_next_upstream_tries 2;
        proxy_connect_timeout 300ms;
        proxy_pass http://off_upstream;
    }
}
--- request eval
["GET /breakeroff/", "GET /breakeroff/", "GET /breakeroff/", "GET /breakeroff/"]
--- error_code eval
[200, 200, 200, 200]
--- response_headers_like eval
[
    "X-Cache: (?!BREAKER-503)",
    "X-Cache: (?!BREAKER-503)",
    "X-Cache: (?!BREAKER-503)",
    "X-Cache: (?!BREAKER-503)",
]
# threshold=3, weight=3 biases the peer picker to try the dead peer first on
# (at least) 3 of every 4 selections: with the flag off, only the FINAL
# attempt (the healthy retry -> 200) is ever recorded per request, so this
# is a run of SUCCESSES, not failures -- the breaker must never trip
# regardless of how many requests touched the dead peer along the way. This
# is the "unchanged without the opt-in" half of the done criterion.

=== TEST 2: flag ON -- a single request whose own retries burn through 3 dead peers trips the breaker, and the VERY NEXT request lands on the now-OPEN breaker with no origin contact
--- http_config eval
qq{
    cache_turbo_zone on_zone 16m;

    upstream on_upstream {
        server 127.0.0.1:$::deadA max_fails=0;
        server 127.0.0.1:$::deadB max_fails=0;
        server 127.0.0.1:$::deadC max_fails=0;
        server 127.0.0.1:$::aliveN max_fails=0;
    }

    server {
        listen       127.0.0.1:$::aliveN;
        server_name  alive_on;
        location / {
            add_header Cache-Control "no-store" always;
            return 200 "origin-alive-on\\n";
        }
    }
}
--- config eval
qq{
    location = /breakeron/ {
        cache_turbo on_zone;
        cache_turbo_key \$uri\$request_id;
        cache_turbo_valid 1;
        cache_turbo_breaker on;
        cache_turbo_breaker_threshold 3;
        cache_turbo_breaker_window 30;
        cache_turbo_breaker_count_retries on;
        proxy_next_upstream error timeout;
        proxy_next_upstream_tries 4;
        proxy_connect_timeout 300ms;
        proxy_pass http://on_upstream;
    }
}
--- request eval
["GET /breakeron/", "GET /breakeron/"]
--- more_headers eval
["Host: localhost", "Host: localhost"]
--- error_code eval
[200, 503]
--- response_headers_like eval
[
    "X-Cache: (?!BREAKER-503)",
    "X-Cache: BREAKER-503",
]
# BOTH requests in ONE block/ONE nginx process/ONE shm zone -- deliberately
# not split across two `=== TEST` blocks: Test::Nginx::Util only restarts
# nginx when the `--- config` STRING changes, so two blocks with identical
# config would (correctly) reuse the same process/zone, but a same-process
# reuse was observed during development to also carry forward request-
# composition state (the client's Host header) across the block boundary in
# a way this harness's public API gives no control over -- see the request
# eval array here as the reliable alternative: one block, two ordered
# requests, exactly the "keep the connection semantics under the harness's
# own control" pattern ci/t/core/304-freshening.t uses for its own ordered
# request sequence.
#
# request 1: round-robin tries all 3 dead peers (proxy_next_upstream_tries 4
#   allows exactly that many attempts) then lands on the healthy 4th, so
#   this ONE request's own upstream_states array holds 3 failed entries
#   before the final successful one -- enough to reach breaker_threshold=3
#   via ngx_http_cache_turbo_breaker_retry_failures() alone. The response
#   itself is still 200 (nothing has told the CLIENT anything is wrong yet).
# request 2: THE assertion. With nothing armed to serve stale
#   (cache_turbo_valid 1, no keep_stale/use_stale configured here), an OPEN
#   breaker answers locally: 503 + X-Cache: BREAKER-503, no origin contact
#   at all -- direct proof request 1's own retries pushed the counter to
#   threshold. This is the "now trips where it previously did not" half of
#   the done criterion; TEST 1 proves the identical dead-peer-then-healthy-
#   retry traffic pattern never trips the breaker with the flag off, no
#   matter how many requests it runs across.
