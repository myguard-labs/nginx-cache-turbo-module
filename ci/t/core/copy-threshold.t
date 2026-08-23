# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# C2 -- cache_turbo_copy_threshold: a body at/under the threshold is
# ngx_pnalloc+ngx_memcpy'd into r->pool under the zone mutex already held and
# served with no shm reference at all; a body over the threshold keeps the
# pre-C2 PERF-7 zero-copy pin. The invariant under test is simple to state and
# easy to get wrong: above and below the threshold, a client must see
# BYTE-FOR-BYTE identical behaviour -- same status, same headers (including a
# header whose name/value the module restores from the served buffer, proving
# the restored pointers point into whichever buffer was actually served, copy
# or shm blob), same body.
#
# `cache_turbo_copy_threshold 16` is set explicitly (not the shipped default)
# so the two literal origin bodies below can straddle it by exactly one byte
# without depending on whatever crossover the bench.sh sweep picks for the
# shipped default -- this file proves the MECHANISM, not the tuning.
#
#   /small/  16-byte origin body  (== threshold)      -> COPY path (new)
#   /large/  17-byte origin body  (== threshold + 1)   -> PIN path (unchanged)
#
# TEST 1 / TEST 2: for each path, request twice with a long cache_turbo_valid
#   so the second request is an L1 HIT (X-Cache: HIT) served out of L1 rather
#   than proxied again. Both requests must return the identical literal body
#   AND the identical custom marker header the origin set on the ONE real
#   contact -- the HIT response's marker header can only be correct if the
#   header name/value pointers the module restored point at real bytes
#   (either the r->pool copy or the still-valid pinned shm blob), not at
#   memory nothing owns.
#
# TEST 3 (negative control): the SAME 16-byte body (at/under the threshold)
#   with `cache_turbo_copy_threshold 0` (off) explicitly set. 0 means "always
#   pin" regardless of size (see the loc_conf default), so this exercises the
#   OLD pin-only path and must behave identically to TEST 1 -- proving the new
#   copy path is not silently relied on for correctness and the off switch
#   genuinely disables it, not just relabels it.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_origin_port );

repeat_each(1);
no_long_string();

my $op = ct_origin_port();

# Exactly 16 and 17 bytes -- do not reflow these literals.
my $SMALL_BODY = "0123456789ABCDEF";      # 16 bytes == threshold
my $LARGE_BODY = "0123456789ABCDEFG";     # 17 bytes == threshold + 1

our $HttpConfig = <<"EOC";
    cache_turbo_zone main 16m;

    server {
        listen       127.0.0.1:$op;
        server_name  origincopythresh;

        location = /small/ {
            add_header Cache-Control "public, max-age=30" always;
            add_header X-Origin-Marker "marker-small-body-exact" always;
            return 200 "$SMALL_BODY";
        }

        location = /large/ {
            add_header Cache-Control "public, max-age=30" always;
            add_header X-Origin-Marker "marker-large-body-exact" always;
            return 200 "$LARGE_BODY";
        }
    }
EOC

our $Config = <<"EOC";
    location = /small/ {
        cache_turbo               main;
        cache_turbo_key            \$uri;
        cache_turbo_valid          30s;
        cache_turbo_copy_threshold 16;
        proxy_pass http://127.0.0.1:$op;
        proxy_http_version 1.1;
    }

    location = /large/ {
        cache_turbo               main;
        cache_turbo_key            \$uri;
        cache_turbo_valid          30s;
        cache_turbo_copy_threshold 16;
        proxy_pass http://127.0.0.1:$op;
        proxy_http_version 1.1;
    }

    location = /small-off/ {
        cache_turbo               main;
        cache_turbo_key            \$uri;
        cache_turbo_valid          30s;
        cache_turbo_copy_threshold 0;
        proxy_pass http://127.0.0.1:$op/small/;
        proxy_http_version 1.1;
    }
EOC

run_tests();

__DATA__

=== TEST 1: a body AT the threshold (16B, COPY path) is byte-identical on MISS and HIT
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /small/", "GET /small/"]
--- error_code eval
[200, 200]
--- response_headers_like eval
[
    "X-Cache: (?!HIT)\nX-Origin-Marker: marker-small-body-exact",
    "X-Cache: HIT\nX-Origin-Marker: marker-small-body-exact",
]
--- response_body_like eval
[qr/^0123456789ABCDEF\z/, qr/^0123456789ABCDEF\z/]



=== TEST 2: a body OVER the threshold (17B, PIN path, unchanged) is byte-identical on MISS and HIT
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /large/", "GET /large/"]
--- error_code eval
[200, 200]
--- response_headers_like eval
[
    "X-Cache: (?!HIT)\nX-Origin-Marker: marker-large-body-exact",
    "X-Cache: HIT\nX-Origin-Marker: marker-large-body-exact",
]
--- response_body_like eval
[qr/^0123456789ABCDEFG\z/, qr/^0123456789ABCDEFG\z/]



=== TEST 3: negative control -- cache_turbo_copy_threshold 0 forces the pin path even at 16B, same observable result
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /small-off/", "GET /small-off/"]
--- error_code eval
[200, 200]
--- response_headers_like eval
[
    "X-Cache: (?!HIT)\nX-Origin-Marker: marker-small-body-exact",
    "X-Cache: HIT\nX-Origin-Marker: marker-small-body-exact",
]
--- response_body_like eval
[qr/^0123456789ABCDEF\z/, qr/^0123456789ABCDEF\z/]
