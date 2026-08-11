# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Preset ENGINE test: a preset's key_cookies[] list (tier 3) folds each
# present cookie's VALUE into the cache key instead of bypassing on it, and
# folds EVERY listed cookie that is present, not just the first.
#
# This is a pure ADDITION, not a port: ci/tools/test_runtime.py has no
# engine-level (multi-cookie) key_cookies test. Its only key-cookie coverage is
# test_key_cookie() (the single-cookie DIY cache_turbo_key_cookie directive,
# already ported to key_cookie in this same run) and per-preset single-cookie
# legs such as magento's X-Magento-Vary in ci/t/presets/magento.t. Nothing in
# the Python suite exercises a preset with MORE THAN ONE key_cookies entry
# folding together, so nothing here is deleted from test_runtime.py.
#
# This is a cross-cutting engine test, not a preset test: it lives in
# ci/t/preset-engine/, not ci/t/presets/. It rides on the invision preset only
# as the vehicle for the multi-cookie fold mechanism (src/ngx_http_cache_turbo_
# module.c, ct_invision_key_cookies[] = { "ips4_hasJS", "ips4_theme",
# "ips4_language", NULL }) -- invision's own row coverage (URI/arg/predicate
# rules) stays out of scope here.
#
# WHY VALUE-KEYING, NOT BYPASSING
# ---------------------------------
# ips4_hasJS/ips4_theme/ips4_language are cosmetic (JS-detection flag, theme
# choice, locale) and shared by every visitor who picked the same values --
# never an identity signal. Bypassing on them would send every anonymous
# visitor with a non-default theme or locale to the origin uncached; folding
# their VALUES into the key gives each combination its own cache entry while
# still caching.
#
# WHY "EVERY present cookie is folded, not just the first" NEEDS ITS OWN TEST
# -------------------------------------------------------------------------
# ngx_http_cache_turbo_key_cookie() (src/ngx_http_cache_turbo_module.c) is
# driven by a cursor that must advance past each match and keep scanning the
# preset's key_cookies[] array. A single-cookie preset (magento) cannot
# distinguish "folds every listed cookie" from "folds only the first listed
# cookie" -- both look identical with one cookie. TEST 3 sets only the SECOND
# and THIRD cookies (ips4_theme, ips4_language) with ips4_hasJS absent, so a
# scanner that stops after the first miss would silently drop both remaining
# folds and collapse this case onto the all-absent anonymous entry.
#
# The framing itself (0x1f tag + 4B namelen + 4B vallen, unforgeable against
# splicing) is common code shared with the single-cookie case and is not
# re-verified here -- see ci/t/presets/magento.t TEST 6-8 for the Cookie-
# header-scan and exact-name guarantees, which apply identically per cookie.
#
# See ci/t/presets/magento.t for the same value-keyed-not-bypassed pattern:
# every case below is asserted through a --- response_body_like match on the
# origin's Cookie echo (see ci/t/lib/CacheTurbo.pm ct_http_config), because an
# X-Cache header alone cannot distinguish "correctly separated entry" from
# "wrongly shared entry" -- only the echoed body proves which bucket answered.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

our $Config = ct_config(
    { path => '/inv/', backend => 'invision' },
);

run_tests();

__DATA__

=== TEST 1: a single key_cookies entry value-keys its own entry (same value HITs)
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /inv/page-a", "GET /inv/page-a"]
--- more_headers eval
["Cookie: ips4_theme=dark", "Cookie: ips4_theme=dark"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- response_body_like eval
[qr/ips4_theme=dark/, qr/ips4_theme=dark/]
--- error_code eval
[200, 200]



=== TEST 2: a DIFFERENT value on that same cookie must not see the first value's entry
# The body echo proves separation -- an X-Cache sequence alone would only show
# the fetch was not a HIT, not that it got its own distinct body.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /inv/page-b", "GET /inv/page-b",
 "GET /inv/page-b", "GET /inv/page-b"]
--- more_headers eval
["Cookie: ips4_theme=dark", "Cookie: ips4_theme=dark",
 "Cookie: ips4_theme=light", "Cookie: ips4_theme=light"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- response_body_like eval
[qr/ips4_theme=dark/, qr/ips4_theme=dark/,
 qr/ips4_theme=light/, qr/ips4_theme=light/]
--- error_code eval
[200, 200, 200, 200]



=== TEST 3: EVERY present key cookie is folded, not just the first
# ips4_hasJS is ABSENT here; only ips4_theme and ips4_language (the SECOND and
# THIRD entries in ct_invision_key_cookies[]) are set. A scanner that stops
# after the first miss would drop both and collapse this onto the
# all-absent anonymous entry from TEST 5 -- the response_body_like values below
# rule that out directly.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /inv/page-c", "GET /inv/page-c",
 "GET /inv/page-c", "GET /inv/page-c"]
--- more_headers eval
["Cookie: ips4_theme=dark; ips4_language=de",
 "Cookie: ips4_theme=dark; ips4_language=de",
 "Cookie: ips4_theme=dark; ips4_language=fr",
 "Cookie: ips4_theme=dark; ips4_language=fr"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- response_body_like eval
[qr/ips4_language=de/, qr/ips4_language=de/,
 qr/ips4_language=fr/, qr/ips4_language=fr/]
--- error_code eval
[200, 200, 200, 200]



=== TEST 4: ALL THREE key cookies present, each contributes -- changing any one alone must miss the full-set entry
# Each pair below holds two of the three fixed and moves the third, so every
# slot of ct_invision_key_cookies[] is exercised as the ONLY thing that changed.
# Varying just the first (ips4_hasJS) would leave the later two unpinned
# whenever the first is present: TEST 3 covers ips4_theme/ips4_language with
# ips4_hasJS ABSENT, which is a different scan path -- a fold that stops after
# the first MATCH (rather than the first miss) still passes TEST 3, and only
# the ips4_theme and ips4_language pairs here catch it.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /inv/page-d", "GET /inv/page-d",
 "GET /inv/page-d", "GET /inv/page-d",
 "GET /inv/page-d", "GET /inv/page-d",
 "GET /inv/page-d", "GET /inv/page-d"]
--- more_headers eval
["Cookie: ips4_hasJS=1; ips4_theme=dark; ips4_language=de",
 "Cookie: ips4_hasJS=1; ips4_theme=dark; ips4_language=de",
 "Cookie: ips4_hasJS=0; ips4_theme=dark; ips4_language=de",
 "Cookie: ips4_hasJS=0; ips4_theme=dark; ips4_language=de",
 "Cookie: ips4_hasJS=1; ips4_theme=light; ips4_language=de",
 "Cookie: ips4_hasJS=1; ips4_theme=light; ips4_language=de",
 "Cookie: ips4_hasJS=1; ips4_theme=dark; ips4_language=fr",
 "Cookie: ips4_hasJS=1; ips4_theme=dark; ips4_language=fr"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- response_body_like eval
[qr/ips4_hasJS=1; ips4_theme=dark; ips4_language=de/,
 qr/ips4_hasJS=1; ips4_theme=dark; ips4_language=de/,
 qr/ips4_hasJS=0; ips4_theme=dark; ips4_language=de/,
 qr/ips4_hasJS=0; ips4_theme=dark; ips4_language=de/,
 qr/ips4_hasJS=1; ips4_theme=light; ips4_language=de/,
 qr/ips4_hasJS=1; ips4_theme=light; ips4_language=de/,
 qr/ips4_hasJS=1; ips4_theme=dark; ips4_language=fr/,
 qr/ips4_hasJS=1; ips4_theme=dark; ips4_language=fr/]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200]



=== TEST 5: the cookie-less anonymous entry is its own bucket, distinct from any folded combination
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /inv/page-e", "GET /inv/page-e",
 "GET /inv/page-e", "GET /inv/page-e"]
--- more_headers eval
["", "",
 "Cookie: ips4_theme=dark; ips4_language=de",
 "Cookie: ips4_theme=dark; ips4_language=de"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- response_body_like eval
[qr/ck=$/, qr/ck=$/,
 qr/ips4_theme=dark/, qr/ips4_theme=dark/]
--- error_code eval
[200, 200, 200, 200]



=== TEST 6: an unrelated cookie ahead of a key cookie in the same header must not mask it
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /inv/page-f", "GET /inv/page-f",
 "GET /inv/page-f", "GET /inv/page-f"]
--- more_headers eval
["Cookie: ips4_theme=dark", "Cookie: ips4_theme=dark",
 "Cookie: session_id=zzz; ips4_theme=dark", "Cookie: session_id=zzz; ips4_theme=dark"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: HIT}, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]
