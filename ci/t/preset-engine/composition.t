# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Preset ENGINE test: `cache_turbo_backend woocommerce` alone must silently
# IMPLY the wordpress preset. Ported from test_auto_backend_composition() and
# test_woo_implies_wordpress_wp_admin() in ci/tools/test_runtime.py, both
# DELETED by this port.
#
# This is a cross-cutting engine test, not a preset test: it lives in
# ci/t/preset-engine/, not ci/t/presets/. It exercises the preset-composition
# resolver itself (parse-time implication), not woocommerce's or wordpress's
# own rule rows -- those stay in ci/t/presets/woocommerce.t and wordpress.t.
#
# WHY THE IMPLICATION EXISTS
# ---------------------------
# WooCommerce is an add-on TO WordPress. It ships no /wp-admin/ URI rule and
# no wordpress_logged_in_ cookie rule of its own -- WordPress core owns both.
# Naming `woocommerce` alone therefore used to leave the entire WP admin
# surface, and every WP-authenticated session, uncovered on a woo-only
# backend: an operator who ran WooCommerce without also writing
# `cache_turbo_backend wordpress woocommerce;` got a cache that served a
# logged-in customer's page, or the admin dashboard, to every anonymous
# visitor. The fix resolves `woocommerce` to `{woocommerce, wordpress}` at
# config-parse time, so the implied rules are always present.
#
# THREE HALVES, ALL REQUIRED
# ----------------------------
#   * a WP login cookie must NOW skip on a woo-only location (the leak the
#     implication closes -- TEST 2);
#   * /wp-admin/ must skip under a woo-only backend, proven through
#     cache_turbo_backend_prefix so the preset's byte-0-anchored URI rule can
#     even be reached from a subdirectory mount (TEST 3), with a same-mount
#     ordinary page as the control that the skip is the URI rule firing and
#     not the whole location going pass-through (TEST 3b);
#   * an anonymous page with NEITHER cookie must still cache (TEST 1b) -- the
#     implication only ADDS bypass rules, it must never turn a location into
#     unconditional pass-through. A bug that composed by disabling caching
#     entirely would pass TEST 2/3 for the wrong reason without this control.
#
# See ci/t/preset-engine/arg-scanner.t for why every bypass case below is
# fetched TWICE via `--- request eval` arrays: a bypass and a first-time MISS
# both come back with no X-Cache header, so a single fetch would pass with the
# implication removed entirely.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

our $Config = ct_config(
    { path => '/woo/', backend => 'woocommerce',
      extra => 'cache_turbo_key $uri$is_args$args;' },
    { path => '/wooshop/', backend => 'woocommerce',
      extra => 'cache_turbo_backend_prefix /wooshop/;' },
);

run_tests();

__DATA__

=== TEST 1: a woo session cookie bypasses (woo's own rule)
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /woo/cartpage", "GET /woo/cartpage"]
--- more_headers eval
["Cookie: woocommerce_cart_hash=abc123", "Cookie: woocommerce_cart_hash=abc123"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 1b: an anonymous page (no woo, no wp cookie) still caches
# The implication must only ADD bypass rules, never disable caching wholesale.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /woo/anonpage", "GET /woo/anonpage"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 2: woocommerce implies wordpress -- a WP login cookie ALSO bypasses
# Before the implication this cached a logged-in customer's page for every
# visitor: woocommerce carries no wordpress_logged_in_ rule of its own.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /woo/wppage", "GET /woo/wppage"]
--- more_headers eval
["Cookie: wordpress_logged_in_x=1", "Cookie: wordpress_logged_in_x=1"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 3: the IMPLIED wordpress /wp-admin/ URI rule fires under woo-only
# /wooshop/ names ONLY woocommerce; cache_turbo_backend_prefix rebases
# /wooshop/wp-admin/* onto /wp-admin/* for the preset URI matcher, so a HIT
# here would be the exact leak (cacheable wp-admin under a woo-only backend).
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wooshop/wp-admin/index", "GET /wooshop/wp-admin/index"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 3b: control -- an ordinary page under the same woo-only mount still caches
# Proves the skip in TEST 3 is the rebased /wp-admin/ URI rule firing, not the
# whole /wooshop/ location going pass-through.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wooshop/shop/product", "GET /wooshop/shop/product"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
