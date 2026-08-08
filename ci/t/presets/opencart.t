# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# OpenCart preset (docs/opencart.md). Ported from
# test_opencart_route_args_bypass() and
# test_opencart_session_cookie_is_not_a_login_signal() in ci/tools/test_runtime.py,
# deleted by this port. The `location /opencart/` fixture in test_runtime.py's
# config is NOT touched: `/redmine/` sits right next to it in the same block and
# is untouched by this preset, so nothing here removes the location wholesale --
# only the two test functions and their run_all() calls.
#
# ARG-TIER ONLY -- NO URI ROW, DELIBERATELY
# ------------------------------------------------------------------------
# Verbatim gist from the ct_opencart_* header comment in src:
#
#   OpenCart routes everything through index.php?route=<controller>, so every
#   private page shares the single path /index.php. A URI-prefix rule catches
#   NOTHING here -- it would look correct, match nothing, and leave carts and
#   account pages cacheable. The `route=account/` and `route=checkout/`
#   prefixes cover the whole private surface. `user_token` is the admin-panel
#   auth arg and `customer_token` the login-validation token.
#
#   The route values are ENUMERATED, not prefix-matched: the arg tier compares
#   NAME=VALUE by exact bytes (no case folding, no prefix match), so a
#   `route=account/` row would match only the literal ?route=account/ and
#   never ?route=account/login. Every private route is therefore listed in
#   full. ADDING A ROUTE MEANS ADDING A ROW; a new private controller under
#   account/ or checkout/ is NOT covered automatically.
#
# NO COOKIE ROW, DELIBERATELY
# ------------------------------------------------------------------------
#   `OCSESSID` is issued to guests -- a shop has to track an anonymous cart --
#   and login state lives in $this->session->data['customer'], SERVER-SIDE
#   ONLY. The cookie value is an opaque session id whose guest and customer
#   forms are identical on the wire, so there is nothing for nginx to test.
#   Adding `OCSESSID` here would bypass every visitor and disable the cache.
#
# Both matcher tables are NULL (ct_opencart_cookies[] and ct_opencart_uris[]
# are `{ NULL }`), so this preset has no URI oracle and no cookie oracle --
# the only mutation target for the arg matcher is ngx_http_cache_turbo_arg_match()
# itself (src ~4214).
#
# ct_opencart_args[] carries several prefix-related-looking route pairs
# ("route=checkout/payment_address" / "route=checkout/payment_method" and
# similar), but the matcher compares NAME=VALUE by EXACT BYTES, not prefix --
# so unlike the discourse/xenforo/yabb URI-tier prefix trap, no row here is a
# byte-prefix of another IN THE SENSE THAT MATTERS for the matcher (an exact
# "route=checkout/payment_address" never matches a request carrying
# "route=checkout/payment_method"). No extra positive arm is needed for that
# reason; TEST 3 still exercises a representative spread of the enumerated
# rows so each half of the table (checkout/*, account/*) is proven reachable
# rather than just the first row.
#
# See ci/t/presets/discourse.t for why every bypass case is fetched TWICE (a
# bypass and a first-time MISS both lack X-Cache) and why these are
# `--- request eval` arrays rather than `--- pipelined_requests`.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

# opencart is entirely path-independent (everything lives on /index.php), so
# every location below is keyed on $is_args$args -- a bare $uri key would
# collapse every ?route= variant onto one cache entry and mask the arg-tier
# rows outright. /oc/ carries the arg-tier cases. /gen/ is the isolation
# control -- a DIFFERENT preset.
our $Config = ct_config(
    { path => '/oc/',  backend => 'opencart',
      extra => 'cache_turbo_key $uri$is_args$args;' },
    { path => '/gen/', backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: every checkout/* route bypasses
# The checkout/* half of ct_opencart_args[].
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /oc/index.php?route=checkout/cart",             "GET /oc/index.php?route=checkout/cart",
 "GET /oc/index.php?route=checkout/checkout",          "GET /oc/index.php?route=checkout/checkout",
 "GET /oc/index.php?route=checkout/confirm",           "GET /oc/index.php?route=checkout/confirm",
 "GET /oc/index.php?route=checkout/success",           "GET /oc/index.php?route=checkout/success",
 "GET /oc/index.php?route=checkout/failure",           "GET /oc/index.php?route=checkout/failure",
 "GET /oc/index.php?route=checkout/payment_address",   "GET /oc/index.php?route=checkout/payment_address",
 "GET /oc/index.php?route=checkout/payment_method",    "GET /oc/index.php?route=checkout/payment_method",
 "GET /oc/index.php?route=checkout/shipping_address",  "GET /oc/index.php?route=checkout/shipping_address",
 "GET /oc/index.php?route=checkout/shipping_method",   "GET /oc/index.php?route=checkout/shipping_method",
 "GET /oc/index.php?route=checkout/register",          "GET /oc/index.php?route=checkout/register"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200,
 200, 200, 200, 200, 200]



=== TEST 2: every account/* route bypasses
# The account/* half of ct_opencart_args[].
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /oc/index.php?route=account/account",         "GET /oc/index.php?route=account/account",
 "GET /oc/index.php?route=account/login",           "GET /oc/index.php?route=account/login",
 "GET /oc/index.php?route=account/logout",          "GET /oc/index.php?route=account/logout",
 "GET /oc/index.php?route=account/register",        "GET /oc/index.php?route=account/register",
 "GET /oc/index.php?route=account/forgotten",       "GET /oc/index.php?route=account/forgotten",
 "GET /oc/index.php?route=account/edit",            "GET /oc/index.php?route=account/edit",
 "GET /oc/index.php?route=account/password",        "GET /oc/index.php?route=account/password",
 "GET /oc/index.php?route=account/address",         "GET /oc/index.php?route=account/address",
 "GET /oc/index.php?route=account/order",           "GET /oc/index.php?route=account/order",
 "GET /oc/index.php?route=account/wishlist",        "GET /oc/index.php?route=account/wishlist",
 "GET /oc/index.php?route=account/download",        "GET /oc/index.php?route=account/download",
 "GET /oc/index.php?route=account/returns",         "GET /oc/index.php?route=account/returns",
 "GET /oc/index.php?route=account/reward",          "GET /oc/index.php?route=account/reward",
 "GET /oc/index.php?route=account/transaction",     "GET /oc/index.php?route=account/transaction",
 "GET /oc/index.php?route=account/subscription",    "GET /oc/index.php?route=account/subscription",
 "GET /oc/index.php?route=account/newsletter",      "GET /oc/index.php?route=account/newsletter",
 "GET /oc/index.php?route=account/affiliate",       "GET /oc/index.php?route=account/affiliate",
 "GET /oc/index.php?route=account/custom_field",    "GET /oc/index.php?route=account/custom_field",
 "GET /oc/index.php?route=account/tracking",        "GET /oc/index.php?route=account/tracking",
 "GET /oc/index.php?route=account/payment_method",  "GET /oc/index.php?route=account/payment_method",
 "GET /oc/index.php?route=account/authorize",       "GET /oc/index.php?route=account/authorize",
 "GET /oc/index.php?route=account/success",         "GET /oc/index.php?route=account/success"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200,
 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200,
 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200]



=== TEST 3: user_token and customer_token both bypass (bare-name rows)
# Both are bare-NAME rows (no `=value` half), so presence alone is the signal.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /oc/index.php?route=api/login&user_token=deadbeef",     "GET /oc/index.php?route=api/login&user_token=deadbeef",
 "GET /oc/index.php?route=api/order&customer_token=cafebabe", "GET /oc/index.php?route=api/order&customer_token=cafebabe"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 4: catalogue routes on the SAME /index.php path stay cacheable
# The negative control: an ordinary product page goes through the identical
# path with a different route value and must still cache. A test asserting
# only the bypass rows would also pass if the preset bypassed /index.php
# outright, which would disable the cache for the whole shop.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /oc/index.php?route=common/home",       "GET /oc/index.php?route=common/home",
 "GET /oc/index.php?route=product/category",  "GET /oc/index.php?route=product/category",
 "GET /oc/index.php?route=product/product",   "GET /oc/index.php?route=product/product"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 5: an unrelated arg does not bypass
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /oc/index.php?route=product/category&sort=price", "GET /oc/index.php?route=product/category&sort=price"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 6: OCSESSID guest-issued session cookie does NOT bypass
# OpenCart must ship NO cookie row -- OCSESSID is guest-issued and login
# state lives server-side only, so a browsing shopper carrying it must stay
# cacheable. Without this row a cookie rule here would bypass the entire shop.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: OCSESSID=b7d3f1a9c2e4550188aa
--- request eval
["GET /oc/index.php?route=product/category&path=20", "GET /oc/index.php?route=product/category&path=20"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 7: same ?route=checkout/cart revisited is still bypass, never a false HIT
# $is_args$args is in the key specifically so a bypass row is not quietly
# masked by a path-only key that would otherwise make repeat traffic for the
# SAME route value look like an ordinary cacheable entry once bypass logic is
# disturbed.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /oc/index.php?route=checkout/cart", "GET /oc/index.php?route=checkout/cart",
 "GET /oc/index.php?route=checkout/cart", "GET /oc/index.php?route=checkout/cart"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 8: OCSESSID under /gen/ (wordpress backend) still HITs
# Isolation control. wordpress has its own cookie list and opencart's
# (absent) cookie row does not leak across backends.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: OCSESSID=b7d3f1a9c2e4550188aa
--- request eval
["GET /gen/product-iso", "GET /gen/product-iso"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
