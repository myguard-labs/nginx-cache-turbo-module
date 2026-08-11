# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Preset ENGINE test: cache_turbo_backend_prefix rebases r->uri before the
# preset URI tier runs. Ported from test_backend_prefix_subdir() in
# ci/tools/test_runtime.py (item 18), which is DELETED by this port.
# test_backend_prefix_rejected() (the nginx -t config-time rejection of a
# malformed prefix value) is a config-validation test, not a runtime engine
# test, and stays in Python.
#
# This is a cross-cutting engine test, not a preset test: it lives in
# ci/t/preset-engine/, not ci/t/presets/. It rides on the wordpress preset
# only as the vehicle for the rebase mechanism -- wordpress's own row
# coverage stays in ci/t/presets/wordpress.t.
#
# THE BUG
# --------
# Preset uris[] rows are literals anchored at byte 0 of r->uri ("/wp-admin/").
# A WordPress site mounted at a subdirectory, e.g. /shop/, therefore matches
# NO URI rule at all: r->uri is "/shop/wp-admin/...", which does not start
# with "/wp-admin/". The entire admin surface silently becomes cacheable the
# moment the install is not at the domain root.
#
# THE FIX
# --------
# cache_turbo_backend_prefix rebases r->uri onto the configured mount before
# the preset URI tier runs, so "/shop/wp-admin/" is matched as "/wp-admin/"
# for rule purposes. Six legs, all required:
#   * TEST 1 -- the bug, still live on a location WITHOUT the directive. If
#     this ever reads BYPASS, the fix landed somewhere global and every
#     assertion below proves nothing.
#   * TEST 2/2b -- the fix: the SAME path, mounted WITH the directive, now
#     bypasses via the rebase. TEST 2b is a second needle (wp-login.php) so
#     the rebase is not proven special-cased to one rule.
#   * TEST 3 -- OUTSIDE the mount: backend_prefix is /shop/ but the request
#     path starts with /elsewhere/, so the rebase must not fire. A
#     misconfigured mount degrades to today's (buggy-by-design) behaviour
#     rather than force-matching.
#   * TEST 4 -- the segment-boundary check survives the rebase:
#     "/shop/wp-adminfoo" rebases to "/wp-adminfoo", where a letter continues
#     past the needle, so it must NOT match "/wp-admin/".
#   * TEST 5 -- a normal page under the mount still caches: the rebase must
#     bypass only the matched rule, not the whole mounted subtree.
#
# Every bypass case is fetched TWICE via `--- request eval` arrays: a bypass
# and a first-time MISS both come back with no X-Cache header, so a single
# fetch would pass with the rebase removed entirely (see
# ci/t/preset-engine/arg-scanner.t for the same pattern).

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

our $Config = ct_config(
    { path => '/shop/', backend => 'wordpress',
      extra => 'cache_turbo_backend_prefix /shop/;' },
    # Directive value deliberately does NOT match this location's own path:
    # requests here reach the module with backend_prefix set to /shop/ while
    # r->uri starts with /elsewhere/, the ONLY way to exercise the no-rebase
    # branch (a request routed to /shop/ always starts with it).
    { path => '/elsewhere/', backend => 'wordpress',
      extra => 'cache_turbo_backend_prefix /shop/;' },
    { path => '/noshop/', backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: THE BUG -- without the directive, /wp-admin/ is cacheable
# If this ever reads BYPASS, the fix landed somewhere global and every
# assertion below proves nothing.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /noshop/wp-admin/", "GET /noshop/wp-admin/"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 2: THE FIX -- with the directive, the rebased path bypasses
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /shop/wp-admin/", "GET /shop/wp-admin/"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 2b: a second rebased needle -- the rebase is not special-cased to one rule
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /shop/wp-login.php", "GET /shop/wp-login.php"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 3: OUTSIDE the mount -- backend_prefix must not force-match
# A misconfigured mount leaves the URI alone rather than force-matching --
# it degrades to today's (buggy-by-design) caching behaviour.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /elsewhere/wp-admin/", "GET /elsewhere/wp-admin/"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 4: the segment boundary survives the rebase
# "/shop/wp-adminfoo" rebases to "/wp-adminfoo" -- the byte after the needle
# is a letter, so it must NOT match "/wp-admin/".
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /shop/wp-adminfoo", "GET /shop/wp-adminfoo"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 5: a normal page under the mount still caches
# The rebase must bypass only the matched rule, not the whole mounted subtree.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /shop/about", "GET /shop/about"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
