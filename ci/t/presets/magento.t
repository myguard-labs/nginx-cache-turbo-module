# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Magento 2 preset (docs/magento.md). Ported from test_magento_preset() in
# ci/tools/test_runtime.py.
#
# NO COOKIE-BYPASS TIER, NO ARG RULES, ONE KEY COOKIE
# ----------------------------------------------------------------------------
# ct_magento_cookies[] and ct_magento_args[] are both {NULL} -- the magento row
# in ngx_http_cache_turbo_presets[] carries NULL for cookie_preds too, so this
# file has no cookie-bypass leg, no arg-rule leg and no predicate leg. Only the
# URI-bypass leg and the key-cookie leg apply.
#
# X-MAGENTO-VARY IS VALUE-KEYED, NOT BYPASSED -- exactly as Magento's own
# reference VCL does it (vcl_hash: hash_data of the regsub'd cookie) and as
# Magento's built-in PHP FPC does it (Identifier.php folds COOKIE_VARY_STRING
# into the cache id). The cookie is a SEGMENT FINGERPRINT (sha256 over
# {customer_group, customer_logged_in, store, currency}), not an identity: many
# visitors legitimately share one value, and Magento's private-content JS keeps
# the cart OUT of the cached HTML.
#
# Bypassing on it (what this preset used to do) was safe but sent every
# non-default ANONYMOUS visitor -- a guest in a second currency, a second store
# view -- to the origin with no private data at all. Presence-KEYING would be
# the actual leak (it collapses guest-EUR + wholesale + logged-in-retail into
# one bucket); value-keying is neither.
#
# THE URI LIST IS THE HEADER-AUTHENTICATED SURFACE TOO
# ----------------------------------------------------------------------------
# /rest and /soap are the Web API front names (app/code/Magento/Webapi/etc/
# di.xml: frontName "rest" / "soap"), and they are the surface the cookie tier
# is structurally blind to: `GET /rest/V1/customers/me` with
# `Authorization: Bearer <token>` returns that customer's data with NO cookie
# involved. No cookie rule can see it -- the URI rule is what stops the LOOKUP
# as well as the store. /graphql is the same class.
#
# EVERY ct_magento_uris[] ROW IS SLASH-LESS -- THE BOUNDARY-BYTE BRANCH IS LIVE
# ----------------------------------------------------------------------------
# Unlike joomla's "/administrator/" (which already ends in '/' and never
# reaches the trailing-byte check), every row here -- "/checkout", "/customer",
# "/rest", ... "/health_check.php" -- is a slash-less needle. Each one exercises
# ngx_http_cache_turbo_uri_prefix()'s boundary-byte branch (next byte must be
# '/', '.', or EOF) for real. TEST 2 is the byte-0 segment-termination negative
# for this preset: "/customerX" begins with "/customer"'s bytes at position 0
# but has no boundary byte after them, so the rule must NOT fire -- sent
# directly, not nested under the real prefix (the vacuous-test trap).
#
# See ci/t/presets/xenforo.t for why every bypass case is fetched TWICE and why
# these are `--- request eval` arrays rather than `--- pipelined_requests`.
# See ci/t/presets/mybb.t for the exact-vs-suffix key/predicate asymmetry (not
# exercised here directly -- magento has no predicate leg -- but TEST 9 pins
# the same exact-name property on the key-cookie side).

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config ct_origin_port );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

# The transition-race test (TEST 9) needs an origin response that ESTABLISHES
# the segment -- i.e. carries a genuine upstream Set-Cookie -- not one stamped
# on afterwards by add_header on the cache_turbo location. add_header runs at
# the OUTPUT filter, after cache_turbo has already decided whether to store, so
# a Set-Cookie added there is invisible to the storage floor and the test would
# be vacuous. A second, dedicated origin server on its own port supplies a real
# upstream Set-Cookie instead.
our $MgVaryOriginPort = ct_origin_port() + 4;
our $HttpConfigExtra = $HttpConfig . <<"EOC";
    server {
        listen       127.0.0.1:$MgVaryOriginPort;
        server_name  mgvary-origin;
        location / {
            add_header Cache-Control "public, max-age=30" always;
            add_header Set-Cookie "X-Magento-Vary=established123" always;
            return 200 "origin:\$request_uri:\$connection:\$connection_requests:\$msec\\n";
        }
    }
EOC

# The preset's URI rules are prefixes anchored at byte 0, so each one gets its
# own ROOT location. /mg/ carries the key-cookie cases, which are
# path-independent. /mgvary/ is a SEPARATE location that proxies to the
# dedicated Set-Cookie-emitting origin above -- the transition-race fixture,
# kept apart from /mg/ so its Set-Cookie does not contaminate the ordinary
# key-cookie bodies. /gen/ is the isolation control -- a DIFFERENT preset,
# proving the magento rows are opt-in and do not leak into another backend's
# location.
our $Config = ct_config(
    { path => '/checkout',              backend => 'magento' },
    { path => '/customer',              backend => 'magento' },
    { path => '/graphql',               backend => 'magento' },
    { path => '/rest',                  backend => 'magento' },
    { path => '/soap',                  backend => 'magento' },
    { path => '/sales',                 backend => 'magento' },
    { path => '/newsletter',            backend => 'magento' },
    { path => '/wishlist',              backend => 'magento' },
    { path => '/paypal',                backend => 'magento' },
    { path => '/review',                backend => 'magento' },
    { path => '/page_cache/block/esi',  backend => 'magento' },
    { path => '/health_check.php',      backend => 'magento' },
    { path => '/mg/',                   backend => 'magento' },
    { path => '/gen/',                  backend => 'wordpress' },
) . <<"EOL";
        location /mgvary/ {
            cache_turbo         main;
            cache_turbo_backend magento;
            cache_turbo_key     \$uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:$MgVaryOriginPort/;
        }
EOL

run_tests();

__DATA__

=== TEST 1: every magento URI rule bypasses
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /checkout/cart", "GET /checkout/cart",
 "GET /customer/account", "GET /customer/account",
 "GET /graphql", "GET /graphql",
 "GET /rest/V1/customers/me", "GET /rest/V1/customers/me",
 "GET /soap/default", "GET /soap/default",
 "GET /sales/order/view", "GET /sales/order/view",
 "GET /newsletter/manage", "GET /newsletter/manage",
 "GET /wishlist/index/index", "GET /wishlist/index/index",
 "GET /paypal/express/review", "GET /paypal/express/review",
 "GET /review/product/list", "GET /review/product/list",
 "GET /page_cache/block/esi/getEsi", "GET /page_cache/block/esi/getEsi",
 "GET /health_check.php", "GET /health_check.php"]
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
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200,
 200, 200, 200, 200, 200, 200, 200, 200, 200]



=== TEST 2: byte-0 segment-termination negative -- a merely-similar sibling is NOT covered
# THE KNOWN VACUOUS-TEST TRAP: the lookalike must be sent DIRECTLY at byte 0, not
# nested under the real prefix, or the test would still pass with the whole rule
# deleted. "/customerX" begins with the needle's bytes "/customer" at position 0
# but has no boundary byte ('/', '.', EOF) after them, so
# ngx_http_cache_turbo_uri_prefix() fails the trailing-byte check and the URI
# never bypasses -- hence it must HIT on the second fetch.
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /customerX", "GET /customerX"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 3: X-Magento-Vary is VALUE-KEYED -- same value hits its own entry
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- more_headers
Cookie: X-Magento-Vary=9f2a4c1e8b7d6f5a4c3b2a1908070605
--- request eval
["GET /mg/product-a", "GET /mg/product-a"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 4: a DIFFERENT vary value must NOT see the first value's entry
# The leak the old presence-keying rejection was worried about, and the whole
# point of keying on the VALUE rather than on presence. The body echo proves
# separation -- an X-Cache sequence alone would only show the fetch was not a
# HIT, not that it got its own distinct body.
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /mg/product-b", "GET /mg/product-b",
 "GET /mg/product-b", "GET /mg/product-b"]
--- more_headers eval
["Cookie: X-Magento-Vary=9f2a4c1e8b7d6f5a4c3b2a1908070605",
 "Cookie: X-Magento-Vary=9f2a4c1e8b7d6f5a4c3b2a1908070605",
 "Cookie: X-Magento-Vary=0000111122223333444455556666777",
 "Cookie: X-Magento-Vary=0000111122223333444455556666777"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- response_body_like eval
[qr/Vary=9f2a4c1e/, qr/Vary=9f2a4c1e/,
 qr/Vary=00001111/, qr/Vary=00001111/]
--- error_code eval
[200, 200, 200, 200]



=== TEST 5: the cookie-less anonymous entry is its OWN third bucket
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /mg/product-c", "GET /mg/product-c",
 "GET /mg/product-c", "GET /mg/product-c"]
--- more_headers eval
["", "",
 "Cookie: X-Magento-Vary=9f2a4c1e8b7d6f5a4c3b2a1908070605",
 "Cookie: X-Magento-Vary=9f2a4c1e8b7d6f5a4c3b2a1908070605"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- response_body_like eval
[qr/ck=$/, qr/ck=$/,
 qr/Vary=9f2a4c1e/, qr/Vary=9f2a4c1e/]
--- error_code eval
[200, 200, 200, 200]



=== TEST 6: ALL Cookie headers are collected -- a split header must key identically
# A client may split its cookies over several Cookie headers; if only the first
# were scanned, an attacker could hide the real cookie in a second header and
# CHOOSE which bucket to read. Requests 1-2 carry X-Magento-Vary in a SECOND
# Cookie header; requests 3-4 fold the same pair into one header. Both pairs
# must key to the same entry.
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /mg/split", "GET /mg/split",
 "GET /mg/split", "GET /mg/split"]
--- more_headers eval
["Cookie: PHPSESSID=abc\nCookie: X-Magento-Vary=aaaa1111bbbb2222",
 "Cookie: PHPSESSID=abc\nCookie: X-Magento-Vary=aaaa1111bbbb2222",
 "Cookie: PHPSESSID=abc; X-Magento-Vary=aaaa1111bbbb2222",
 "Cookie: PHPSESSID=abc; X-Magento-Vary=aaaa1111bbbb2222"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: HIT}, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]



=== TEST 7: a matching cookie pair must never end the scan
# The scan must not stop at the first Cookie pair it inspects. An unrelated
# pair AHEAD of X-Magento-Vary in the same header must not mask it.
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /mg/scan-order", "GET /mg/scan-order",
 "GET /mg/scan-order", "GET /mg/scan-order"]
--- more_headers eval
["Cookie: X-Magento-Vary=cafebabe11112222",
 "Cookie: X-Magento-Vary=cafebabe11112222",
 "Cookie: unrelated=1; X-Magento-Vary=cafebabe11112222",
 "Cookie: unrelated=1; X-Magento-Vary=cafebabe11112222"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: HIT}, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]



=== TEST 8: a cookie whose name merely ENDS WITH ours is a different cookie
# Keying is EXACT-name (nlen != nmlen fails the match), unlike the tier-2
# predicate engine's suffix match. A loose match here would let an
# attacker-chosen cookie name select the bucket a real X-Magento-Vary reader
# uses. Asserted POSITIVELY: the decoy must land in the SAME bucket as no
# cookie at all (the anonymous entry), not merely "a different bucket than the
# real cookie would pick".
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /mg/decoy", "GET /mg/decoy",
 "GET /mg/decoy", "GET /mg/decoy"]
--- more_headers eval
["", "",
 "Cookie: NOT-X-Magento-Vary=aaaa1111bbbb2222",
 "Cookie: NOT-X-Magento-Vary=aaaa1111bbbb2222"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: HIT}, qq{X-Cache: HIT}]
--- response_body_like eval
[qr/ck=$/, qr/ck=$/,
 qr/ck=$/, qr/ck=$/]
--- error_code eval
[200, 200, 200, 200]



=== TEST 9: THE TRANSITION RACE -- an establishing Set-Cookie must not poison the anonymous key
# The request carries NO vary cookie, so it keys to the ANONYMOUS entry, and
# the origin response itself ESTABLISHES the segment (Set-Cookie:
# X-Magento-Vary=...). Storing that body under the anonymous key would poison
# it for every anonymous visitor. Upstream's own VCL refuses exactly this
# (beresp.uncacheable).
#
# This module inherits the refusal from the UNCONDITIONAL Set-Cookie floor in
# ngx_http_cache_turbo_response_cacheable(): ANY Set-Cookie response is never
# stored, magento-specific or not. This test therefore pins the BEHAVIOUR the
# preset's key-cookie leg depends on, not a magento-only code path -- if the
# floor is ever made optional, this is the assertion that must fail first.
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /mgvary/page", "GET /mgvary/page", "GET /mgvary/page"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200]



=== TEST 10: THE HIT RATE -- anonymous-visitor cookies must keep caching
# Every cookie below is set for ANONYMOUS visitors (session id, CSRF form key,
# private-content cache-buster, mage-cache flag, section data ids). None of
# them is a magento cookie-bypass or key-cookie rule (the preset declares no
# cookie-bypass tier at all). A regression here is a silent 0%-hit-rate
# catalog.
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /mg/cat-PHPSESSID", "GET /mg/cat-PHPSESSID",
 "GET /mg/cat-form_key", "GET /mg/cat-form_key",
 "GET /mg/cat-private_content_version", "GET /mg/cat-private_content_version",
 "GET /mg/cat-mage-cache-sessid", "GET /mg/cat-mage-cache-sessid",
 "GET /mg/cat-section_data_ids", "GET /mg/cat-section_data_ids",
 "GET /mg/cat-all", "GET /mg/cat-all"]
--- more_headers eval
["Cookie: PHPSESSID=abc123", "Cookie: PHPSESSID=abc123",
 "Cookie: form_key=deadbeef", "Cookie: form_key=deadbeef",
 "Cookie: private_content_version=1a2b3c", "Cookie: private_content_version=1a2b3c",
 "Cookie: mage-cache-sessid=true", "Cookie: mage-cache-sessid=true",
 "Cookie: section_data_ids=%7B%22cart%22%3A1%7D", "Cookie: section_data_ids=%7B%22cart%22%3A1%7D",
 "Cookie: PHPSESSID=abc; form_key=def; private_content_version=1a2b; mage-cache-sessid=true; mage-messages=hi",
 "Cookie: PHPSESSID=abc; form_key=def; private_content_version=1a2b; mage-cache-sessid=true; mage-messages=hi"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200]



=== TEST 11: the magento rows do not leak into another backend's location
# /gen/ runs the wordpress preset. /checkout is a magento URI rule, not a
# wordpress one, so the generic location must cache it -- proving the rule is
# preset-scoped, not global.
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /gen/checkout", "GET /gen/checkout"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 12: an X-Magento-Vary cookie does not key under the wordpress preset
# The cookie half of TEST 11. X-Magento-Vary is not a wordpress signal, so the
# generic location must cache it as a plain cookie-less-equivalent request --
# proving the key-cookie rule is preset-scoped.
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- more_headers
Cookie: X-Magento-Vary=9f2a4c1e8b7d6f5a4c3b2a1908070605
--- request eval
["GET /gen/product", "GET /gen/product"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
