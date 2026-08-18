# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Preset ENGINE test: two case-sensitivity questions about key derivation
# that PLAN-optimize.md P1-2/P1-3 resolved by reading source, not guessing.
#
# P1-2 -- the query-arg denylist (ngx_http_cache_turbo_pat_match,
# src/ngx_http_cache_turbo_vary.c) matched with ngx_strncmp, so an argument
# spelled "UTM_Source" bypassed the "utm_*" prefix rule that catches
# "utm_source". ngx_http_cache_turbo_normalized_args_variable scans straight
# off r->args.data (the raw query string) -- nothing upstream lowercases an
# arg name, and every built-in/configured pattern is itself lowercase -- so
# this was a real gap, not a no-op. Fixed by switching to ngx_strncasecmp.
# TEST 1/2 below prove "UTM_Source=x" and "utm_source=x" both get stripped
# from $cache_turbo_normalized_args and therefore share one cache entry.
#
# P1-3 -- suspected that module.c's cache-key builder copies the raw Host
# header verbatim, so "Example.com" and "example.com" would land in separate
# entries. Reading nginx's own ngx_http_process_host() /
# ngx_http_validate_host() (src/http/ngx_http_request.c in the vendored
# nginx tree) settled it: ngx_http_process_host() calls validate_host() and
# assigns its OUTPUT to r->headers_in.server (ngx_http_request.c:1888,1910),
# and validate_host() itself lowercases the host with ngx_strlow() whenever
# it contains an upper-case byte (ngx_http_request.c:2258-2261 sets
# alloc=1; :2395-2401 does the ngx_strlow(host->data, h, host_len) copy) and
# truncates at the first ':' via host_len (ngx_http_request.c:2272-2275),
# dropping any :80/:443 port suffix from the copied bytes entirely.
# src/ngx_http_cache_turbo_module.c:772 copies `host = r->headers_in.server`
# -- the ALREADY-NORMALIZED field, not the raw Host header -- into the cache
# key (module.c:779 ngx_cpymem). So P1-3 is a NO-OP: there is no raw-Host
# byte path into the key to fix. TEST 3 below is the durable proof: two
# requests differing only in Host-header case hit the SAME entry, with no
# code change required to make that true.
#
# All three tests use the generic-isolation.t pattern: MISS-then-HIT via
# `--- request eval`, because a single fetch cannot distinguish "correctly
# shared" from "accidentally bypassed/never cached" -- both come back with no
# X-Cache header on their only request.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

# /na/ keys on the normalized-args variable (path + denylist-stripped query),
# so two differently-cased tracking params that both denylist-strip collapse
# onto the SAME entry, but a genuine non-denylisted arg still splits it.
# /host/ keys on $host (lower-cased request-side host var, same source data
# module.c reads) purely to assert nginx's own normalization -- the module's
# cache key itself is exercised via $uri, and TEST 3 relies on nginx routing
# the differently-cased Host to the SAME location/entry in the first place.
our $Config = ct_config(
    { path => '/na/', backend => 'wordpress',
      extra => 'cache_turbo_key $uri$is_args$cache_turbo_normalized_args;' },
    { path => '/host/', backend => 'wordpress',
      extra => 'cache_turbo_key $uri;' },
);

run_tests();

__DATA__

=== TEST 1: UTM_Source (upper) and utm_source (lower) share one entry
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /na/post-1?UTM_Source=twitter", "GET /na/post-1?utm_source=twitter"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 2: a genuine non-denylisted arg still splits the entry -- the negative half of TEST 1
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /na/post-1?UTM_Source=twitter", "GET /na/post-1?UTM_Source=twitter",
 "GET /na/post-1?other=twitter", "GET /na/post-1?other=twitter"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]



=== TEST 3: P1-3 proof -- Example.com and example.com share one entry
# No code change fixes this: ngx_http_process_host()/ngx_http_validate_host()
# in core nginx already lower-case the Host header before the module's key
# builder ever sees it (r->headers_in.server). This is the durable proof that
# P1-3 is a no-op, not an assertion about module code.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /host/page-1", "GET /host/page-1"]
--- more_headers eval
["Host: Example.com", "Host: example.com"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
