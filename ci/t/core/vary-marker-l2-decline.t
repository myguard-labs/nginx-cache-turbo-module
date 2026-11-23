# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# CT-VARY-REVAL-L2-DECLINE-DEMOTE -- auto-Vary marker revalidation must fail
# open to the resident L1 entry when the L2 marker GET cannot run.
#
# With an L2 backend configured, vary_apply() arms the c-2 marker
# revalidation once a warm L1 marker is cache_turbo_vary_marker_revalidate
# (default 2s) old. access_l1() then skips its fresh/stale serve arms so the
# request reaches access_l2_marker_get(). When that GET declines (connect
# refused, connect backoff, alloc failure) or fails after parking, nothing
# re-served the resident node: with cache_turbo_lock off a fresh variant
# inside cache_turbo_valid was answered EXPIRED and refetched from the
# origin. With the lock on, the cold-miss CLAIM_FRESH re-lookup masked it.
#
# THE L2 PEER is 127.0.0.1:1. Nothing listens there and an unprivileged
# process cannot bind it, and it lies outside Test::Nginx's randomized
# 1988-65534 port range, so a parallel .t's nginx can never answer on it.
# Every connect is refused, which is the "L2 configured but down" case.
# Depending on the platform that refusal surfaces synchronously (the marker
# GET declines at launch; connect backoff then keeps later GETs declining)
# or after the GET parks. TEST 5 pins the parked path deterministically:
# its "L2" is the origin HTTP server, which accepts the connection and
# answers the Redis GET with an HTTP 400, so the GET parks and lands
# NGX_ERROR (malformed reply).
#
# The elapsed time is real wall-clock time via `--- wait: N` (sleeps N
# seconds after each request in the list except the last). 3s guarantees a
# marker age >= 2 on ngx_time()'s whole-second clock, far inside the 30s
# cache_turbo_valid.
#
# TEST 1: lock off, after the window -- the defect. MISS, HIT, HIT; before
#         the fix the second and third requests were EXPIRED.
# TEST 2: lock off, within the window (no wait) -- boundary: the
#         revalidation never arms, HIT on every build.
# TEST 3: lock on, after the window -- boundary: HIT on every build (the
#         CLAIM_FRESH re-lookup used to mask the defect; the fix must not
#         regress it).
# TEST 4: lock off, after the window, cache_turbo_vary_marker_revalidate 0
#         -- negative control isolating the revalidation arm: identical
#         timing and dead peer, revalidation disabled, HIT on every build.
# TEST 5: lock off, after the window, L2 peer answers garbage -- the parked
#         GET fails with NGX_ERROR instead of declining at launch. MISS,
#         HIT, HIT; before the fix the second and third were EXPIRED.
#
# Each block uses its own URI under one shared config, so one nginx serves
# the file and no block sees another's entries.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_origin_port );

repeat_each(1);
no_long_string();

our $Op = ct_origin_port();

our $HttpConfig = <<"EOC";
    cache_turbo_zone main 16m;

    server {
        listen       127.0.0.1:$Op;
        server_name  origin;

        location / {
            add_header Cache-Control "public, max-age=30" always;
            add_header Vary "User-Agent" always;
            return 200 "origin:\$request_uri:\$connection:\$connection_requests:\$msec\n";
        }
    }
EOC

sub reval_location {
    my ($path, $extra, $l2) = @_;
    $l2 //= '127.0.0.1:1';
    return <<"EOL";
        location $path {
            cache_turbo          main;
            cache_turbo_key      \$request_uri;
            cache_turbo_valid    30s;
            cache_turbo_redis    $l2 prefix=ctvrd: timeout=250ms;
$extra
            add_header           X-CT-Status \$cache_turbo_status always;
            proxy_pass http://127.0.0.1:$Op/;
        }
EOL
}

our $Config = reval_location('/reval-nolock/', '            cache_turbo_lock     off;')
            . reval_location('/reval-lock/',   '            cache_turbo_lock     on;')
            . reval_location('/reval-off/',
                  "            cache_turbo_lock     off;\n"
                . '            cache_turbo_vary_marker_revalidate 0;')
            . reval_location('/reval-garbage/', '            cache_turbo_lock     off;',
                  "127.0.0.1:$Op");

run_tests();

__DATA__

=== TEST 1: lock off, L2 down, marker older than the window -- warm variant stays a HIT
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
User-Agent: Mozilla/5.0 (X11; Linux x86_64)
--- request eval
["GET /reval-nolock/after", "GET /reval-nolock/after", "GET /reval-nolock/after"]
--- wait: 3
--- response_headers eval
[qq{X-CT-Status: MISS}, qq{X-CT-Status: HIT}, qq{X-CT-Status: HIT}]
--- error_code eval
[200, 200, 200]



=== TEST 2: lock off, L2 down, within the window -- revalidation never arms
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
User-Agent: Mozilla/5.0 (X11; Linux x86_64)
--- request eval
["GET /reval-nolock/within", "GET /reval-nolock/within", "GET /reval-nolock/within"]
--- response_headers eval
[qq{X-CT-Status: MISS}, qq{X-CT-Status: HIT}, qq{X-CT-Status: HIT}]
--- error_code eval
[200, 200, 200]



=== TEST 3: lock on, L2 down, marker older than the window -- stays a HIT
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
User-Agent: Mozilla/5.0 (X11; Linux x86_64)
--- request eval
["GET /reval-lock/after", "GET /reval-lock/after", "GET /reval-lock/after"]
--- wait: 3
--- response_headers eval
[qq{X-CT-Status: MISS}, qq{X-CT-Status: HIT}, qq{X-CT-Status: HIT}]
--- error_code eval
[200, 200, 200]



=== TEST 4: revalidation off (0), lock off, L2 down, after the window -- negative control
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
User-Agent: Mozilla/5.0 (X11; Linux x86_64)
--- request eval
["GET /reval-off/after", "GET /reval-off/after", "GET /reval-off/after"]
--- wait: 3
--- response_headers eval
[qq{X-CT-Status: MISS}, qq{X-CT-Status: HIT}, qq{X-CT-Status: HIT}]
--- error_code eval
[200, 200, 200]



=== TEST 5: lock off, L2 answers garbage (parked GET fails), marker older than the window -- stays a HIT
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
User-Agent: Mozilla/5.0 (X11; Linux x86_64)
--- request eval
["GET /reval-garbage/after", "GET /reval-garbage/after", "GET /reval-garbage/after"]
--- wait: 3
--- response_headers eval
[qq{X-CT-Status: MISS}, qq{X-CT-Status: HIT}, qq{X-CT-Status: HIT}]
--- error_code eval
[200, 200, 200]
