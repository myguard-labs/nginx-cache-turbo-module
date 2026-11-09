# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Shopware 6 preset (docs/shopware6.md). Ported from test_shopware6_preset() in
# ci/tools/test_runtime.py.
#
# SW-CACHE-HASH IS VALUE-KEYED, NOT BYPASSED -- SAME SHAPE AS MAGENTO
# ----------------------------------------------------------------------------
# sw-cache-hash is a purpose-built cache-variant cookie, not an identity.
# CacheHeadersService::buildCacheHash() folds a SET of fields into it --
# {rule_ids, version_id, currency_id, tax_state, logged_in_state} -- where
# logged_in_state is literally 'logged-in' | 'not-logged-in'
# (CacheHeadersService.php:104). Shopware's own reverse proxy treats it exactly
# as a key and never as a bypass (shopware/varnish-shopware default.vcl:
# hash_data("+context=" + cookie.get("sw-cache-hash"))).
#
# WHY A BYPASS WOULD BE WRONG, precisely: isCacheHashRequired() (:125) returns
# true for a logged-in customer OR a guest with a filled cart OR a guest on a
# non-default currency -- so bypass-on-presence would send cart-holding GUESTS
# and non-default-currency GUESTS to the origin, anonymous visitors whose
# private data is not in the cached HTML at all (the cart is fetched
# client-side, as in magento). That is the exact bypass #28 removed from
# magento; do not reintroduce it here.
#
# LAZY, and actively so -- Shopware enforces it harder than any other preset
# here. When the hash is NOT required, applyCacheHash() does not merely omit
# the cookie, it DELETES a stale one (removeCookie + clearCookie). A default
# anonymous visitor is guaranteed cookieless, so the anonymous bucket is the
# common case (TEST 5).
#
# SW-STATES IS DELIBERATELY NOT MATCHED, AND MATCHING IT WOULD BE A LEAK
# ----------------------------------------------------------------------------
# It was REMOVED in 6.8 (UPGRADE-6.8.md: "Removed `sw-states` and
# `sw-currency` cache cookie handling ... The complete caching behaviour is now
# controlled by the `sw-cache-hash` cookie"); HttpCacheKeyGenerator::
# SYSTEM_STATE_COOKIE is @deprecated tag:v6.8.0. A preset keyed on sw-states
# alone would silently stop firing on an upgraded shop. sw-cache-hash spans
# 6.4..6.8, so one exact literal covers every supported line. TEST 10 pins
# sw-states as a non-bypass, positively (via $cache_turbo_status), because an
# empty bypass-cookie list would pass a bare `x-cache == HIT` assert for free.
#
# NO ARG RULES, ONE PREDICATE -- URI, KEY-COOKIE AND ONE EQ-PREDICATE LEG
# ----------------------------------------------------------------------------
# ct_shopware6_cookies[] and ct_shopware6_args[] are both {NULL}. The row carries
# one cookie predicate: sw-cache-hash EQ "not-cacheable" (TEST 3b), Shopware's
# own "do not cache this visitor" marker. The URI-bypass leg (TEST 1, 1b), the
# key-cookie leg (TEST 2-9) and that predicate apply.
#
# /account, /checkout, /admin, /api and /store-api are all slash-less needles
# except /store-api which itself has no trailing slash either -- every row in
# ct_shopware6_uris[] exercises ngx_http_cache_turbo_uri_prefix()'s
# boundary-byte branch (next byte must be '/', '.', or EOF) for real. TEST 1b
# is the byte-0 segment-termination negative for this preset: "/accountX"
# begins with "/account"'s bytes at position 0 but has no boundary byte after
# them, so the rule must NOT fire -- sent directly, not nested under the real
# prefix (the vacuous-test trap).
#
# See ci/t/presets/xenforo.t for why every bypass case is fetched TWICE and why
# these are `--- request eval` arrays rather than `--- pipelined_requests`.
# See ci/t/presets/mybb.t for the exact-vs-suffix key/predicate asymmetry (not
# exercised here directly -- shopware6 has no predicate leg -- but TEST 8 pins
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
our $SwHashOriginPort = ct_origin_port() + 4;
our $HttpConfigExtra = $HttpConfig . <<"EOC";
    server {
        listen       127.0.0.1:$SwHashOriginPort;
        server_name  swhash-origin;
        location / {
            add_header Cache-Control "public, max-age=30" always;
            add_header Set-Cookie "sw-cache-hash=established123" always;
            return 200 "origin:\$request_uri:\$connection:\$connection_requests:\$msec\\n";
        }

        # Shopware >= 6.7.15 storefront page: CacheResponseSubscriber.php:84-90
        # calls CacheHeadersService::applyCacheHeaders() for every response
        # with a SalesChannelContext, which echoes the context language and
        # currency (:39-40) and merges HttpCacheVariantHeaders::HEADERS into
        # Vary (:42-45, HttpCacheVariantHeaders.php:25-31). Symfony's
        # Response::sendHeaders() emits one `Vary:` line per value, so the five
        # axes arrive as five header lines. No Set-Cookie: a cookieless guest
        # page. The body echoes the variant headers so a bypassed request is
        # visibly answered by the origin for ITS values.
        location /vary/ {
            add_header Cache-Control "public, max-age=30" always;
            add_header sw-language-id "2fbb5fe2e29a4d70aa5854ce7ce3e20b" always;
            add_header sw-currency-id "b7d2554b0ce847cd82f3ac9bd1c0dfca" always;
            add_header Vary "sw-access-key" always;
            add_header Vary "sw-language-id" always;
            add_header Vary "sw-currency-id" always;
            add_header Vary "sw-include-seo-urls" always;
            add_header Vary "sw-cache-hash" always;
            return 200 "vary:\$request_uri:\$connection:\$connection_requests:\$msec:cur=\$http_sw_currency_id:lang=\$http_sw_language_id\\n";
        }

        # The same five axes on ONE comma-joined line, plus sw-context-token:
        # an axis the preset does not own. It must stay uncacheable -- the
        # rows satisfy only their own names, never the whole Vary line.
        location /varyx/ {
            add_header Cache-Control "public, max-age=30" always;
            add_header Vary "sw-access-key, sw-language-id, sw-currency-id, sw-include-seo-urls, sw-cache-hash, sw-context-token" always;
            return 200 "varyx:\$request_uri:\$connection:\$connection_requests:\$msec\\n";
        }

        location /varyc/ {
            add_header Cache-Control "public, max-age=30" always;
            add_header Vary "Accept-Encoding, sw-access-key, sw-language-id, sw-currency-id, sw-include-seo-urls, sw-cache-hash" always;
            return 200 "varyc:\$request_uri:\$connection:\$connection_requests:\$msec\\n";
        }
    }
EOC

# The preset's URI rules are prefixes anchored at byte 0, so each one gets its
# own ROOT location. /sw/ carries the key-cookie cases, which are
# path-independent. /swhash/ is a SEPARATE location that proxies to the
# dedicated Set-Cookie-emitting origin above -- the transition-race fixture,
# kept apart from /sw/ so its Set-Cookie does not contaminate the ordinary
# key-cookie bodies. /gen/ is the isolation control -- a DIFFERENT preset,
# proving the shopware6 rows are opt-in and do not leak into another backend's
# location.
our $Config = ct_config(
    { path => '/account',   backend => 'shopware6' },
    { path => '/checkout',  backend => 'shopware6' },
    { path => '/admin',     backend => 'shopware6' },
    { path => '/api',       backend => 'shopware6' },
    { path => '/store-api', backend => 'shopware6' },
    { path => '/sw/',       backend => 'shopware6' },
    { path => '/gen/',      backend => 'wordpress' },
) . <<"EOL";
        location /swhash/ {
            cache_turbo         main;
            cache_turbo_backend shopware6;
            cache_turbo_key     \$uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:$SwHashOriginPort/;
        }
        location /swvary/ {
            cache_turbo         main;
            cache_turbo_backend shopware6;
            cache_turbo_key     \$uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:$SwHashOriginPort/vary/;
        }
        location /swvaryx/ {
            cache_turbo         main;
            cache_turbo_backend shopware6;
            cache_turbo_key     \$uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:$SwHashOriginPort/varyx/;
        }
        location /swvaryc/ {
            cache_turbo         main;
            cache_turbo_backend shopware6;
            cache_turbo_key     \$uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:$SwHashOriginPort/varyc/;
        }
        location /wpvary/ {
            cache_turbo         main;
            cache_turbo_backend wordpress;
            cache_turbo_key     \$uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:$SwHashOriginPort/vary/;
        }
EOL

run_tests();

__DATA__

=== TEST 1: every shopware6 URI rule bypasses
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /account/login", "GET /account/login",
 "GET /checkout/cart", "GET /checkout/cart",
 "GET /admin/dashboard", "GET /admin/dashboard",
 "GET /api/product", "GET /api/product",
 "GET /store-api/product", "GET /store-api/product"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200, 200, 200]



=== TEST 1b: byte-0 segment-termination negative -- a merely-similar sibling is NOT covered
# THE KNOWN VACUOUS-TEST TRAP: the lookalike must be sent DIRECTLY at byte 0,
# not nested under the real prefix, or the test would still pass with the
# whole rule deleted. "/accountX" begins with the needle's bytes "/account" at
# position 0 but has no boundary byte ('/', '.', EOF) after them, so
# ngx_http_cache_turbo_uri_prefix() fails the trailing-byte check and the URI
# never bypasses -- hence it must HIT on the second fetch.
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /accountX", "GET /accountX"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 2: sw-cache-hash is VALUE-KEYED -- same value hits its own entry
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- more_headers
Cookie: sw-cache-hash=b1946ac92492d2347c6235b4d2611184
--- request eval
["GET /sw/product-a", "GET /sw/product-a"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 3: a DIFFERENT hash value must NOT see the first value's entry
# The leak the old presence-keying rejection was worried about, and the whole
# point of keying on the VALUE rather than on presence -- logged_in_state is
# folded INTO the value, so this is precisely the logged-in-vs-guest
# separation. The body echo proves separation -- an X-Cache sequence alone
# would only show the fetch was not a HIT, not that it got its own distinct
# body.
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /sw/product-b", "GET /sw/product-b",
 "GET /sw/product-b", "GET /sw/product-b"]
--- more_headers eval
["Cookie: sw-cache-hash=b1946ac92492d2347c6235b4d2611184",
 "Cookie: sw-cache-hash=b1946ac92492d2347c6235b4d2611184",
 "Cookie: sw-cache-hash=591785b794601e212b260e25925636fd",
 "Cookie: sw-cache-hash=591785b794601e212b260e25925636fd"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- response_body_like eval
[qr/ck=sw-cache-hash=b1946ac9/, qr/ck=sw-cache-hash=b1946ac9/,
 qr/ck=sw-cache-hash=591785b7/, qr/ck=sw-cache-hash=591785b7/]
--- error_code eval
[200, 200, 200, 200]



=== TEST 3b: sw-cache-hash=not-cacheable BYPASSES -- Shopware's own opt-out marker
# HttpCacheCookieEvent::NOT_CACHEABLE (:20-25): "bypass the cache for further
# requests"; set for pending flash messages. Keyed alone every such visitor would
# share ONE bucket. Any other hash value still keys and HITs (negative control).
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /sw/product-nc", "GET /sw/product-nc",
 "GET /sw/product-ok", "GET /sw/product-ok"]
--- more_headers eval
["Cookie: sw-cache-hash=not-cacheable",
 "Cookie: sw-cache-hash=not-cacheable",
 "Cookie: sw-cache-hash=not-cacheable-x",
 "Cookie: sw-cache-hash=not-cacheable-x"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]



=== TEST 4: the cookie-less anonymous entry is its OWN third bucket
# The common case -- Shopware actively DELETES sw-cache-hash for an anonymous
# visitor with no cart, so a cookie-less request is not an edge case.
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /sw/product-c", "GET /sw/product-c",
 "GET /sw/product-c", "GET /sw/product-c"]
--- more_headers eval
["", "",
 "Cookie: sw-cache-hash=b1946ac92492d2347c6235b4d2611184",
 "Cookie: sw-cache-hash=b1946ac92492d2347c6235b4d2611184"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- response_body_like eval
[qr/ck=$/, qr/ck=$/,
 qr/ck=sw-cache-hash=b1946ac9/, qr/ck=sw-cache-hash=b1946ac9/]
--- error_code eval
[200, 200, 200, 200]



=== TEST 5: ALL Cookie headers are collected -- a split header must key identically
# A client may split its cookies over several Cookie headers; if only the
# first were scanned, an attacker could hide the real cookie in a second
# header and CHOOSE which bucket to read. Requests 1-2 carry sw-cache-hash in
# a SECOND Cookie header; requests 3-4 fold the same pair into one header.
# Both pairs must key to the same entry.
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /sw/split", "GET /sw/split",
 "GET /sw/split", "GET /sw/split"]
--- more_headers eval
["Cookie: session-=abc\nCookie: sw-cache-hash=aaaa1111bbbb2222",
 "Cookie: session-=abc\nCookie: sw-cache-hash=aaaa1111bbbb2222",
 "Cookie: session-=abc; sw-cache-hash=aaaa1111bbbb2222",
 "Cookie: session-=abc; sw-cache-hash=aaaa1111bbbb2222"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: HIT}, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]



=== TEST 6: a matching cookie pair must never end the scan
# The scan must not stop at the first Cookie pair it inspects. An unrelated
# pair AHEAD of sw-cache-hash in the same header must not mask it.
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /sw/scan-order", "GET /sw/scan-order",
 "GET /sw/scan-order", "GET /sw/scan-order"]
--- more_headers eval
["Cookie: sw-cache-hash=cafebabe11112222",
 "Cookie: sw-cache-hash=cafebabe11112222",
 "Cookie: unrelated=1; sw-cache-hash=cafebabe11112222",
 "Cookie: unrelated=1; sw-cache-hash=cafebabe11112222"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: HIT}, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]



=== TEST 7: a cookie whose name merely ENDS WITH ours is a different cookie
# Keying is EXACT-name (nlen != nmlen fails the match), unlike the tier-2
# predicate engine's suffix match. A loose match here would let an
# attacker-chosen cookie name select the bucket a real sw-cache-hash reader
# uses. Asserted POSITIVELY: the decoy must land in the SAME bucket as no
# cookie at all (the anonymous entry), not merely "a different bucket than the
# real cookie would pick".
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /sw/decoy", "GET /sw/decoy",
 "GET /sw/decoy", "GET /sw/decoy"]
--- more_headers eval
["", "",
 "Cookie: NOT-sw-cache-hash=aaaa1111bbbb2222",
 "Cookie: NOT-sw-cache-hash=aaaa1111bbbb2222"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: HIT}, qq{X-Cache: HIT}]
--- response_body_like eval
[qr/ck=$/, qr/ck=$/,
 qr/ck=$/, qr/ck=$/]
--- error_code eval
[200, 200, 200, 200]



=== TEST 8: THE TRANSITION RACE -- an establishing Set-Cookie must not poison the anonymous key
# The request carries NO sw-cache-hash, so it keys to the ANONYMOUS entry, and
# the origin response itself ESTABLISHES the segment (Set-Cookie:
# sw-cache-hash=...). Storing that body under the anonymous key would poison
# it for every anonymous visitor. Upstream's own Varnish VCL refuses exactly
# this.
#
# This module inherits the refusal from the UNCONDITIONAL Set-Cookie floor in
# ngx_http_cache_turbo_response_policy(): ANY Set-Cookie response is never
# stored, shopware6-specific or not. This test therefore pins the BEHAVIOUR
# the preset's key-cookie leg depends on, not a shopware6-only code path -- if
# the floor is ever made optional, this is the assertion that must fail first.
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /swhash/page", "GET /swhash/page", "GET /swhash/page"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200]



=== TEST 9: sw-states must NOT bypass -- removed in 6.8, matching it would be a leak
# Asserted POSITIVELY via $cache_turbo_status rather than a bare `x-cache ==
# HIT`: shopware6 ships no bypass-cookie list at all, so a bare HIT assert
# would pass just as well with the cookie named zzz-nonsense and guard
# nothing. The first fetch must be a genuine MISS (not BYPASS); the second
# must HIT.
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- more_headers
Cookie: sw-states=logged-in
--- request eval
["GET /sw/states", "GET /sw/states"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 10: the shopware6 rows do not leak into another backend's location
# /gen/ runs the wordpress preset. /account is a shopware6 URI rule, not a
# wordpress one, so the generic location must cache it -- proving the rule is
# preset-scoped, not global.
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /gen/account", "GET /gen/account"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 11: a sw-cache-hash cookie does not key under the wordpress preset
# The cookie half of TEST 10. sw-cache-hash is not a wordpress signal, so a
# request carrying it must fold into the SAME (anonymous, cookie-less) entry
# rather than getting its own key-cookie bucket -- proving the key-cookie rule
# is preset-scoped, not merely that the location caches at all. Request 1 is
# cookie-less and PRIMES the anonymous entry; request 2 carries
# sw-cache-hash and must HIT that same entry. If shopware6's key-cookie
# folding leaked into this location, request 2 would instead MISS into its
# own segmented bucket and this assertion would catch it.
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- more_headers eval
["",
 "Cookie: sw-cache-hash=b1946ac92492d2347c6235b4d2611184"]
--- request eval
["GET /gen/product", "GET /gen/product"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 12: a Shopware 6.7.15+ storefront page (five-axis Vary) is cached for a guest
# CT-PRESET-SHOPWARE-VARY-AXES. Every sales-channel response names
# sw-access-key, sw-language-id, sw-currency-id, sw-include-seo-urls and
# sw-cache-hash in Vary. None is a whitelisted axis, so before the shopware6
# header rows the unknown-axis veto refused every storefront page and this
# location never HIT (observed red: request 2 had no X-Cache). With the rows,
# a guest request carries none of the five, so every stored and served
# representation has all five ABSENT and the Vary is satisfied.
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /swvary/home", "GET /swvary/home",
 "GET /swvaryc/home", "GET /swvaryc/home"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- response_body_like eval
[qr/^vary:\/vary\/home:.*:cur=:lang=$/, qr/^vary:\/vary\/home:.*:cur=:lang=$/,
 qr/^varyc:/, qr/^varyc:/]
--- error_code eval
[200, 200, 200, 200]



=== TEST 13: each Vary axis header bypasses -- never stored, never served the guest copy
# A request carrying any of the five selects a different variant at the same
# URL: RequestTransformer.php:241-243 lets a client-sent sw-language-id (and
# every other request header) override the domain language on Storefront
# routes, SalesChannelRequestContextResolver.php:60-73 honours a client-sent
# sw-currency-id, and HttpCacheKeyGenerator.php:146-150 prefers an
# sw-cache-hash HEADER over the cookie this preset keys on. Per header, on its
# own URL: two header requests first (the guest after them is a MISS, so they
# stored nothing), then a guest HIT, then a header request that must NOT be
# served the guest copy (its body echoes its own currency/language). Row
# removed: that header's request 5 HITs (red).
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /swvary/ak", "GET /swvary/ak", "GET /swvary/ak", "GET /swvary/ak", "GET /swvary/ak",
 "GET /swvary/li", "GET /swvary/li", "GET /swvary/li", "GET /swvary/li", "GET /swvary/li",
 "GET /swvary/ci", "GET /swvary/ci", "GET /swvary/ci", "GET /swvary/ci", "GET /swvary/ci",
 "GET /swvary/su", "GET /swvary/su", "GET /swvary/su", "GET /swvary/su", "GET /swvary/su",
 "GET /swvary/ch", "GET /swvary/ch", "GET /swvary/ch", "GET /swvary/ch", "GET /swvary/ch"]
--- more_headers eval
["sw-access-key: SWSCFIXTURE", "sw-access-key: SWSCFIXTURE", "", "", "sw-access-key: SWSCFIXTURE",
 "sw-language-id: langfixture", "sw-language-id: langfixture", "", "", "sw-language-id: langfixture",
 "sw-currency-id: curfixture", "sw-currency-id: curfixture", "", "", "sw-currency-id: curfixture",
 "sw-include-seo-urls: 1", "sw-include-seo-urls: 1", "", "", "sw-include-seo-urls: 1",
 "SW-Cache-Hash: hashfixture", "SW-Cache-Hash: hashfixture", "", "", "SW-Cache-Hash: hashfixture"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: HIT}, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: HIT}, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: HIT}, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: HIT}, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: HIT}, qq{X-Cache: }]
--- response_body_like eval
[qr/^vary:/, qr/^vary:/, qr/:cur=:lang=$/, qr/:cur=:lang=$/, qr/^vary:/,
 qr/:lang=langfixture$/, qr/:lang=langfixture$/, qr/:cur=:lang=$/, qr/:cur=:lang=$/, qr/:lang=langfixture$/,
 qr/:cur=curfixture:/, qr/:cur=curfixture:/, qr/:cur=:lang=$/, qr/:cur=:lang=$/, qr/:cur=curfixture:/,
 qr/^vary:/, qr/^vary:/, qr/:cur=:lang=$/, qr/:cur=:lang=$/, qr/^vary:/,
 qr/^vary:/, qr/^vary:/, qr/:cur=:lang=$/, qr/:cur=:lang=$/, qr/^vary:/]
--- error_code eval
[200, 200, 200, 200, 200,
 200, 200, 200, 200, 200,
 200, 200, 200, 200, 200,
 200, 200, 200, 200, 200,
 200, 200, 200, 200, 200]



=== TEST 14: NEGATIVE -- a Vary axis the preset does not own still refuses the store
# /swvaryx/ sends the five axes plus sw-context-token. The rows satisfy only
# their own names, so the unknown-axis veto must still hold for the sixth.
# A sw-cache-hash COOKIE is not the sw-cache-hash HEADER row: the cookie
# request keys its own bucket on /swvary/ and HITs it.
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /swvaryx/home", "GET /swvaryx/home",
 "GET /swvary/ck", "GET /swvary/ck"]
--- more_headers eval
["", "",
 "Cookie: sw-cache-hash=c0ffee", "Cookie: sw-cache-hash=c0ffee"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]



=== TEST 15: the shopware6 Vary rows do not leak into another backend's location
# /wpvary/ runs the wordpress preset against the same five-axis origin. With
# no header rows of its own, the unknown-axis veto refuses the page there.
--- http_config eval: $::HttpConfigExtra
--- config eval: $::Config
--- request eval
["GET /wpvary/home", "GET /wpvary/home"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]
