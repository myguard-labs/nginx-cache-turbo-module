# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# P5-4 -- 304 freshening path.
#
# status_ttl() refuses NGX_HTTP_NOT_MODIFIED unconditionally (conf.c rejects
# `cache_turbo_valid 304 ...` at config parse time, so 304 can never appear
# in valid_status; status_ttl() returns -1 for it). That refusal is correct
# for the ordinary capture path -- a 304 carries no body and must never be
# STORED as a representation -- but before this change it also meant there
# was NO way to extend a resident entry's life from a 304: the entry just
# aged out and the next request paid a full blocking regeneration.
#
# This suite proves the freshening path added in
# ngx_http_cache_turbo_shm_freshen() (shm.c) / the new capture-gate branch
# (filters.c, ngx_http_cache_turbo_header_filter_capture): a 304 that answers
# a revalidation for a KNOWN key bumps that key's fresh_until/stale_until in
# place, WITHOUT re-storing a body.
#
# The vehicle is a client-sent conditional GET (If-None-Match) proxied
# straight through to the origin on an EXPIRED-entry refetch -- nginx core
# forwards client request headers to the origin unless something strips
# them, and nothing in this module strips If-None-Match/If-Modified-Since,
# so this reaches the freshening branch without depending on the (separate,
# not-yet-merged) P1-4 SWR-validator-injection row. That keeps this test
# valid however/whenever P1-4 lands later.
#
# ORACLE: the module's own X-Cache debug header (module.c). A serve straight
# off a still-fresh L1 node stamps X-Cache: HIT; a node past BOTH
# fresh_until and stale_until is EXPIRED and falls through to the origin
# instead (access.c), which for these locations means a brand-new 200 with
# no X-Cache: HIT at all. That is a direct, non-flaky proof of "the resident
# node's fresh_until moved forward", not an inference from timing or from a
# response body that could coincidentally repeat.
#
# `cache_turbo_valid 1; cache_turbo_stale_mult 1;` makes fresh_until ==
# stale_until == store-time + 1s, so a 2s wait guarantees the entry is fully
# EXPIRED (not merely stale-but-serveable) before the conditional GET fires
# -- serving STALE straight out of L1 without a round trip would otherwise
# make the test pass without ever reaching the origin at all.
#
# SHARED-ZONE HAZARD: all three test locations below share ONE Config
# string, which Test::Nginx reuses as ONE long-lived nginx process (and
# therefore ONE shm zone) across every `=== TEST` block in this file
# (Test::Nginx::Util's $should_restart only restarts when the config STRING
# changes). TEST 1 deliberately EXPIRES its /fresh304/ entry as part of
# proving freshening -- if TEST 3 (which needs a guaranteed FRESH entry to
# test the UNRELATED client-facing-304 path) reused that same key, it could
# silently inherit TEST 1's post-expiry state instead of starting cold, and
# HAZARD 1's "these two 304s never collide" claim would go unverified while
# the suite still reported green. TEST 3 therefore gets its OWN path
# (/replay304/) with its own cache_turbo_valid, so it always starts from a
# real MISS regardless of execution order or of what TEST 1/TEST 2 left in
# the zone.
#
# ORIGIN CONTRACT (see the `server` block below):
#   /fresh304/    If-None-Match: "fixed" -> 304, no body, Cache-Control
#                                            max-age=5 (longer than the
#                                            store below -- see TEST 1)
#                 otherwise              -> 200, Cache-Control max-age=1,
#                                            ETag "fixed"
#   /cold304/     If-None-Match: "cold"  -> 304, no body (key never stored)
#                 otherwise              -> 200
#   /replay304/   If-None-Match: "fixed" -> 304, no body
#                 otherwise              -> 200, Cache-Control max-age=1,
#                                            ETag "fixed"
#
# TEST 1 (freshening extends survival): populate the entry (GET, no
#   validator -> 200, max-age=1, cached), wait 2s so it is fully EXPIRED,
#   then send the client's OWN conditional GET carrying the matching ETag --
#   the origin answers 304 carrying its OWN longer max-age=5 (honor_cc
#   reads it), which must freshen the resident entry to a 5s window. A
#   third request after a SECOND 2s wait must still be an L1 HIT
#   (X-Cache: HIT) -- the ORIGINAL 1s window cannot possibly survive a
#   second 2s wait (the test's single `--- wait: N` fires between EVERY
#   request pair, so that second wait is unavoidable), so a HIT at request 3
#   can only be explained by the freshening branch having bumped
#   fresh_until forward using the 304's own longer max-age. The asymmetric
#   max-age (1s store vs. 5s freshen) is what makes one uniform wait value
#   able to prove both "the original entry really did expire" (request 2
#   reached the origin, not an L1 stale-serve) and "the freshened entry
#   really did survive" (request 3 is a HIT) in the same block.
#
# TEST 2 (no resident entry -> freshening is a no-op, not a fabrication): a
#   304 for a key this zone never stored must not conjure an entry into
#   existence (shm_freshen()'s NGX_DECLINED arm). A follow-up unconditional
#   GET must be a MISS (no X-Cache: HIT), proving nothing was cached by the
#   bare 304, and the 304 itself must not error.
#
# TEST 3 (client-facing 304 replay is UNCHANGED -- the two 304 kinds do not
#   collide): the pre-existing conditional-HIT path (a module-SYNTHESIZED
#   304 from a FRESH cached entry, ngx_http_cache_turbo_not_modified() in
#   module.c) must still work exactly as before. This is what HAZARD 1
#   warns must not be disturbed -- and structurally cannot be, because
#   ctx->served is already 1 for a synthesized 304, so header_filter()
#   returns before ngx_http_cache_turbo_header_filter_capture() (where the
#   new freshening branch lives) is ever reached for it.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_origin_port );

repeat_each(1);
no_long_string();

my $op = ct_origin_port();

our $HttpConfig = <<"EOC";
    cache_turbo_zone main 16m;

    server {
        listen       127.0.0.1:$op;
        server_name  origin304;

        location = /fresh304/ {
            add_header ETag '"fixed"' always;
            if (\$http_if_none_match = '"fixed"') {
                # The FRESHENING response carries a LONGER max-age than the
                # original store below -- deliberately, so the freshened
                # window (5s) comfortably outlives the SAME --- wait gap
                # (2s) that must ALSO elapse before this 304 fires (to
                # expire the original 1s-TTL entry first). A single uniform
                # `--- wait: N` between every request pair means the wait
                # that expires the ORIGINAL entry is unavoidably paid again
                # between the 304 and the verification request -- honor_cc
                # is what lets the two windows differ.
                add_header Cache-Control "public, max-age=5" always;
                return 304;
            }
            add_header Cache-Control "public, max-age=1" always;
            return 200 "origin-fresh304\\n";
        }

        # No entry is ever stored under this path (TEST 2 sends the
        # conditional request FIRST) -- exists only to answer a 304 for a
        # key the zone has never seen.
        location = /cold304/ {
            if (\$http_if_none_match = '"cold"') {
                return 304;
            }
            add_header Cache-Control "public, max-age=1" always;
            return 200 "origin-cold304\\n";
        }

        # TEST 3's OWN path, distinct from /fresh304/ -- see the
        # SHARED-ZONE HAZARD note above.
        location = /replay304/ {
            add_header Cache-Control "public, max-age=1" always;
            add_header ETag '"fixed"' always;
            if (\$http_if_none_match = '"fixed"') {
                return 304;
            }
            return 200 "origin-replay304\\n";
        }
    }
EOC

our $Config = <<"EOC";
    location = /fresh304/ {
        cache_turbo main;
        cache_turbo_key \$uri;
        cache_turbo_valid 1;
        cache_turbo_stale_mult 1;
        cache_turbo_cache_control honor;
        proxy_pass http://127.0.0.1:$op;
        proxy_http_version 1.1;
    }

    location = /cold304/ {
        cache_turbo main;
        cache_turbo_key \$uri;
        cache_turbo_valid 1;
        cache_turbo_stale_mult 1;
        proxy_pass http://127.0.0.1:$op;
        proxy_http_version 1.1;
    }

    location = /replay304/ {
        cache_turbo main;
        cache_turbo_key \$uri;
        cache_turbo_valid 30;
        proxy_pass http://127.0.0.1:$op;
        proxy_http_version 1.1;
    }
EOC

run_tests();

__DATA__

=== TEST 1: 304 freshens a resident entry -- a request right after it is an L1 HIT, not a fresh origin MISS
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /fresh304/", "GET /fresh304/", "GET /fresh304/"]
--- more_headers eval
["", "If-None-Match: \"fixed\"", ""]
--- wait: 2
--- error_code eval
[200, 304, 200]
--- response_headers_like eval
[
    "X-Cache: (?!HIT)",
    "X-Cache: (?!HIT)",
    "X-Cache: HIT",
]
# request 1: first-ever contact, ordinary MISS -> stored (never HIT). Store
#            uses the plain 200's max-age=1: fresh_until == stale_until ==
#            store-time + 1s, so the FIRST 2s wait fully EXPIRES it (not
#            merely staleness) before request 2 fires -- otherwise request 2
#            would be served STALE straight out of L1 without a round trip,
#            and the conditional GET would never reach the origin at all.
# request 2: the conditional GET reaches the origin (entry is EXPIRED) and
#            gets 304 back, WITH a longer max-age=5 on the 304 itself
#            (honor_cc reads it) -- freshened to a 5s window, deliberately
#            longer than the original 1s. The 304 itself has no body / is
#            not an L1-serve, so "not HIT" is the correct assertion here.
# request 3: THE assertion, after a SECOND 2s wait -- the SAME wait value
#            fires between every request pair, so it is unavoidably paid
#            again here. The original 1s window could never survive a
#            second 2s wait, but the FRESHENED 5s window (from request 2)
#            does. A HIT here therefore cannot be explained by the original
#            store; it can only be explained by the freshening branch
#            having bumped fresh_until forward using the 304's own
#            (longer) max-age.



=== TEST 2: 304 for a key with no resident entry is a safe no-op, not a fabrication
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /cold304/", "GET /cold304/"]
--- more_headers eval
["If-None-Match: \"cold\"", ""]
--- error_code eval
[304, 200]
--- response_headers_like eval
[
    "X-Cache: (?!HIT)",
    "X-Cache: (?!HIT)",
]
# request 1: a 304 with NOTHING resident under this key -- shm_freshen()
#            must decline without crashing or fabricating an entry.
# request 2: unconditional GET must still be a MISS (not HIT) -- proves the
#            bare 304 did not somehow cause this key to be served from L1.



=== TEST 3: client-facing conditional-HIT 304 replay is unchanged by the freshening branch
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /replay304/", "GET /replay304/"]
--- more_headers eval
["", "If-None-Match: \"fixed\""]
--- error_code eval
[200, 304]
--- response_body_like eval
[qr/^origin-replay304/, qr/^$/]
# request 1 populates a FRESH entry on a key /fresh304/ and /cold304/ never
# touch (cache_turbo_valid 30, well within its window at request 2 -- no
# wait between them). Request 2's 304 here is the PRE-EXISTING module.c
# not_modified() rewrite of a cache HIT: ctx->served is already 1 by the
# time header_filter() runs, so it returns before
# ngx_http_cache_turbo_header_filter_capture() (where the new freshening
# branch lives) is ever reached. The client still gets its ordinary
# empty-body 304 straight from the cache, proving the two 304 code paths
# do not collide.
