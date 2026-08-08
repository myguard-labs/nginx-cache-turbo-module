# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# WordPress preset (docs/wordpress.md). Ported from
# test_wordpress_search_and_preview() in ci/tools/test_runtime.py.
#
# URI + arg rules and the login/session-scoped cookie rule. NO key cookies, NO
# value predicates -- this preset is bypass-only (preds = NULL, key_cookies =
# NULL in the registry), so none of those legs apply here.
#
# `ct_wp_cookies[]` = wordpress_logged_in_, wp-postpass_, comment_author_
# `ct_wp_uris[]`    = /wp-admin/, /wp-login.php, /wp-cron.php, /xmlrpc.php,
#                     /wp-json/
# `ct_wp_args[]`    = preview, rest_route
#
# `s` (SITE SEARCH) IS DELIBERATELY ABSENT -- read the block comment above
# ct_wp_cookies[] in src/ngx_http_cache_turbo_module.c before "fixing" this.
# A logged-out visitor's search results are ANONYMOUS-IDENTICAL, so a bypass
# bought no safety (a logged-in editor whose results include drafts is already
# caught by wordpress_logged_in_ on the cookie tier) and cost hit rate. It was
# also actively harmful: a bypass skips the single-flight lock, so a `?s=`
# flood put 100% of its load on the origin, uncollapsed, on the single most
# expensive query WordPress runs. The remedy for unbounded keyspace is
# `cache_turbo_min_uses`, not a blanket bypass. TEST 8-10 assert search
# CACHES; this file is where that inversion is pinned.
#
# The search block uses a DEDICATED location keyed on $request_uri (not the
# suite default $uri) -- ct_location()'s default key is path-only, so without
# the query string in the key, distinct ?s= terms would collide on one entry
# and TEST 9's "distinct terms must not share an entry" would be untestable.
#
# See ci/t/presets/xenforo.t for why every bypass case is fetched TWICE and why
# these are `--- request eval` arrays rather than `--- pipelined_requests`.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

# The preset's URI rules are prefixes anchored at byte 0, so /wp-login.php,
# /wp-cron.php, /xmlrpc.php and /wp-admin/ must be ROOT locations. /wp/ carries
# the cookie and arg cases, which are path-independent. /wpq/ is the search
# location, keyed on $request_uri so distinct ?s= terms land on distinct
# entries. /gen/ is the isolation control -- a DIFFERENT preset, proving the
# wordpress rows are opt-in and do not leak into another backend's location.
our $Config = ct_config(
    { path => '/wp-login.php', backend => 'wordpress' },
    { path => '/wp-cron.php',  backend => 'wordpress' },
    { path => '/xmlrpc.php',   backend => 'wordpress' },
    { path => '/wp-admin/',    backend => 'wordpress' },
    { path => '/wp-json/',     backend => 'wordpress' },
    { path => '/wp/',          backend => 'wordpress' },
    { path => '/wpq/',         backend => 'wordpress',
      extra => 'cache_turbo_key $request_uri;' },
    { path => '/gen/',         backend => 'phpbb' },
);

run_tests();

__DATA__

=== TEST 1: /wp-login.php bypasses on the URI rule
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wp-login.php", "GET /wp-login.php"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 2: /wp-cron.php, /xmlrpc.php and /wp-json/ all bypass
# A scan that stopped at the first row would still pass TEST 1.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wp-cron.php", "GET /wp-cron.php",
 "GET /xmlrpc.php", "GET /xmlrpc.php",
 "GET /wp-json/wp/v2/posts", "GET /wp-json/wp/v2/posts"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 3: /wp-admin/ bypasses -- matched as a directory prefix
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wp-admin/index.php", "GET /wp-admin/index.php"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 4: a URI needle is SEGMENT-TERMINATED -- a lookalike still caches
# /wp-login.php only matches when the next byte is '/', '.' or end-of-URI.
# /wp/wp-loginXphp is neither a real match nor a prefix collision; it must
# cache. (Under the /wp/ location so the request actually reaches the
# wordpress-backed config rather than 404ing with no location match.)
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wp/wp-loginXphp", "GET /wp/wp-loginXphp"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 5: /wp/wp-json-extra (not the real /wp-json/ prefix) still caches
# The needle ends in '/', so it is a plain byte-0 prefix -- "/wp-json-extra"
# does not start with "/wp-json/" and must not bypass.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wp/wp-json-extra", "GET /wp/wp-json-extra"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 6: ?preview=true and ?rest_route= bypass on the ARG rule
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wp/post-1?preview=true", "GET /wp/post-1?preview=true",
 "GET /wp/index.php?rest_route=/wp/v2/posts", "GET /wp/index.php?rest_route=/wp/v2/posts"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 7: an unrelated query arg still caches -- the negative half of TEST 6
# If the arg rule matched on presence of ANY query string, every parameterised
# WordPress URL would bypass and the cache would be off site-wide.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wp/post-1?utm_source=twitter", "GET /wp/post-1?utm_source=twitter"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 8: ?s= site search CACHES -- deliberately NOT a bypass row
# See the file header and the ct_wp_cookies[] block comment in the module
# source. Search results are anonymous-identical for a logged-out visitor, and
# a bypass here would strip the single-flight lock from the most expensive
# query WordPress runs.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wpq/index?s=foo", "GET /wpq/index?s=foo",
 "GET /wpq/index?s=hello+world", "GET /wpq/index?s=hello+world",
 "GET /wpq/?s=x", "GET /wpq/?s=x"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 9: distinct ?s= terms must not share a cache entry
# The X-Cache sequence alone would not prove separation -- request 3 not being
# a HIT only shows it missed SOME entry. The bodies differing is what rules
# out a shared bucket (the location is keyed on $request_uri for exactly this).
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wpq/index?s=alpha", "GET /wpq/index?s=alpha",
 "GET /wpq/index?s=beta", "GET /wpq/index?s=beta"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- response_body_like eval
[qr/index\?s=alpha/, qr/index\?s=alpha/,
 qr/index\?s=beta/, qr/index\?s=beta/]
--- error_code eval
[200, 200, 200, 200]



=== TEST 10: a logged-in editor's search bypasses on the cookie tier
# An editor's search may surface drafts and private posts. The arg tier does
# not cover this at all (search is deliberately not an arg row); the cookie
# tier is what closes it, and it must still fire on a search URL.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: wordpress_logged_in_abc123=alice|1|deadbeef
--- request eval
["GET /wpq/index?s=draft", "GET /wpq/index?s=draft"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 11: a logged-in member (wordpress_logged_in_ cookie) MUST bypass -- THE LEAK GUARD
# Without this rule the member's authenticated page is stored and served to
# strangers.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: wordpress_logged_in_abc123=alice|1|deadbeef
--- request eval
["GET /wp/dashboard", "GET /wp/dashboard"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 12: wp-postpass_ (password-protected post) and comment_author_ also bypass
# Two more rows of ct_wp_cookies[] -- a scan that stopped at the first row
# would still pass TEST 11.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers eval
["Cookie: wp-postpass_abc123=deadbeef", "Cookie: wp-postpass_abc123=deadbeef",
 "Cookie: comment_author_abc123=Alice", "Cookie: comment_author_abc123=Alice"]
--- request eval
["GET /wp/protected-a", "GET /wp/protected-a",
 "GET /wp/protected-b", "GET /wp/protected-b"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 13: the cookie NAME is matched by SUFFIX -- member under any prefix
# ngx_http_cache_turbo_name_has_suffix matches the SUFFIX, so a request-scoped
# or namespaced cookie name (a multisite/proxy prefix) still bypasses. This is
# a deliberate needless-bypass-on-the-safe-side, not a bug.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wp/leak-plain", "GET /wp/leak-plain",
 "GET /wp/leak-pref",  "GET /wp/leak-pref",
 "GET /wp/leak-x",     "GET /wp/leak-x"]
--- more_headers eval
["Cookie: wordpress_logged_in_abc=deadbeef",   "Cookie: wordpress_logged_in_abc=deadbeef",
 "Cookie: xwordpress_logged_in_foo=deadbeef",  "Cookie: xwordpress_logged_in_foo=deadbeef",
 "Cookie: zzwordpress_logged_in_zz=deadbeef",  "Cookie: zzwordpress_logged_in_zz=deadbeef"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 14: wordpress_test_cookie stays cacheable -- it is not a login signal
# WordPress sets `wordpress_test_cookie` on EVERY visit to the login page to
# probe whether cookies are enabled, including for guests who never log in.
# It does not end in any of the three declared cookie suffixes (`_logged_in_`,
# `wp-postpass_`, `comment_author_`), so the suffix matcher has no opinion on
# it and it must not bypass. Guards the xf_session/SMFCookie-class trap: a
# session-plumbing cookie is not a login signal.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: wordpress_test_cookie=WP+Cookie+check
--- request eval
["GET /wp/guest-a", "GET /wp/guest-a"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 15: an EMPTY cookie value still bypasses -- presence alone drives this predicate
# This preset has no value predicate (unlike phpBB/MyBB): the mere PRESENCE of
# a suffix-matching cookie name is the bypass condition, so a cleared/empty
# value must still bypass -- the opposite direction from mybbuser's NONEMPTY
# check, and worth pinning so the two presets are not conflated.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: wordpress_logged_in_abc123=
--- request eval
["GET /wp/guest-b", "GET /wp/guest-b"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 16: a bare valueless cookie (no '=') also bypasses
# Same presence-only reasoning as TEST 15, at the other malformed edge: no '='
# at all. The predicate is presence-of-name, so this must bypass too.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: wordpress_logged_in_abc123
--- request eval
["GET /wp/guest-c", "GET /wp/guest-c"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 17: the wordpress rows do not leak into another backend's location
# /gen/ runs the phpbb preset. The wordpress URI, arg and cookie rules are
# opt-in per location; if the registry ORed every preset's rows together
# instead of selecting by bit, these would bypass here too.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /gen/index.php?rest_route=/wp/v2/posts", "GET /gen/index.php?rest_route=/wp/v2/posts"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 18: a wordpress login cookie does not bypass under the phpbb preset
# The cookie half of TEST 17. wordpress_logged_in_ is not a phpbb signal, so
# the generic location must cache it -- proving the predicate is preset-scoped.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: wordpress_logged_in_abc123=alice|1|deadbeef
--- request eval
["GET /gen/showthread", "GET /gen/showthread"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
