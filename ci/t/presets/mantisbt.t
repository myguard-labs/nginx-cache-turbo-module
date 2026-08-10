# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# MantisBT preset (docs/mantisbt.md). Ported directly from the src table --
# no prior Python test existed for this preset.
#
# THE INSTALL-SELECTED COOKIE PREFIX, AND WHY THE PREDICATES ARE SUFFIXES
# ------------------------------------------------------------------------
# Verbatim from the ct_mantisbt_preds[]/ct_mantisbt_cookies[] header comment
# in src:
#
#   MantisBT. The install-selected cookie prefix is prepended to every
#   symbolic cookie name, so predicates match the invariant suffix.
#   STRING_COOKIE is the login token; the project/list/collapse cookies
#   change a public render and are conservatively bypassed instead of keyed.
#   Mantis form tokens lazily start a native PHP session for anonymous form
#   pages; PHPSESSID is therefore included too (session.name overrides need
#   an operator rule, documented in the guide).
#
# MantisBT's config.inc.php sets $g_cookie_prefix per install (commonly
# "MANTIS", but operator-chosen), and every symbolic cookie MantisBT issues
# is `<prefix>_STRING_COOKIE`, `<prefix>_PROJECT_COOKIE`, etc. -- there is no
# single fixed literal this engine could match with EQ/NE, so the five
# predicate rows below match by SUFFIX instead: `_STRING_COOKIE`,
# `_PROJECT_COOKIE`, `_VIEW_ALL_COOKIE`, `_BUG_LIST_COOKIE`, and
# `_collapse_settings`. TEST 6 proves this works for both the common
# "MANTIS" prefix and an arbitrary install-chosen prefix in the same
# assertion. `ct_mantisbt_args[]` is `{ NULL }` -- no arg tier -- so no arg
# rule is tested here.
#
# THE NONEMPTY OPERATOR -- AN EMPTY VALUE DOES NOT BYPASS
# ------------------------------------------------------------------------
# All five predicate rows use NGX_HTTP_CACHE_TURBO_CVOP_NONEMPTY, unlike
# punbb.t/smf.t's presence-only cookies. A cookie present with an EMPTY value
# must NOT bypass -- TEST 7 pins that negative, the opposite direction from
# punbb.t TEST 8.
#
# THE URI LIST -- SLASH TERMINATED VS SEGMENT TERMINATED, BOTH LIVE HERE
# ------------------------------------------------------------------------
# "/admin/" and "/api/" are DIRECTORY prefixes (trailing slash): the boundary
# byte after the needle is always consumed by the slash itself, so
# "/admin/x" matches but the bare "/admin" (no trailing slash) does NOT --
# it is one byte short of the needle. TEST 2 is this exact oracle. Every
# other row ("/login.php", "/signup.php", ...) is a bare slash-less script
# name, so the byte-after-needle boundary check is LIVE the same way as
# phorum.t's "/admin.php" and punbb.t's "/login.php": the next byte must be
# '/', '.' or end-of-URI. TEST 4 is the segment-termination oracle
# ("/login.phpXX" continues with 'X', neither boundary byte nor EOF, and
# must CACHE); TEST 5 covers the two positive boundary arms.
#
# See ci/t/presets/xenforo.t for why every bypass case is fetched TWICE (a
# bypass and a first-time MISS both lack X-Cache) and why these are
# `--- request eval` arrays rather than `--- pipelined_requests`.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

# Root-anchored prefix locations for a representative slice of the URI table,
# plus the trailing-slash rows and their bare-path negatives. /mantisbt/
# carries the path-independent cookie/predicate cases. /gen/ is the
# isolation control -- a DIFFERENT preset.
our $Config = ct_config(
    { path => '/admin/',                     backend => 'mantisbt' },
    { path => '/adminx',                     backend => 'mantisbt' },
    { path => '/api/',                       backend => 'mantisbt' },
    { path => '/login.php',                  backend => 'mantisbt' },
    { path => '/login_page.php',             backend => 'mantisbt' },
    { path => '/signup.php',                 backend => 'mantisbt' },
    { path => '/lost_pwd.php',               backend => 'mantisbt' },
    { path => '/bug_report.php',             backend => 'mantisbt' },
    { path => '/account_page.php',           backend => 'mantisbt' },
    { path => '/mantisbt/',                  backend => 'mantisbt' },
    { path => '/gen/',                       backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: representative URI rows bypass at the root, with no cookie
# A representative slice of the full ct_mantisbt_uris[] table, each on its
# own path so a shared key cannot mask a missing row.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /login.php",       "GET /login.php",
 "GET /login_page.php",  "GET /login_page.php",
 "GET /signup.php",      "GET /signup.php",
 "GET /lost_pwd.php",    "GET /lost_pwd.php",
 "GET /bug_report.php",  "GET /bug_report.php",
 "GET /account_page.php","GET /account_page.php"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200]



=== TEST 2: DIRECTORY ROWS -- /admin/x and /api/x bypass, /adminx does NOT
# "/admin/" and "/api/" carry a trailing slash, so the boundary byte after
# the needle is always the slash itself: a request whose path merely shares
# the text "admin" but is not followed by that slash ("/adminx") is NOT
# inside the matched subtree and must stay cacheable, while "/admin/x" and
# "/api/x" are. Served under a dedicated /adminx location (distinct from
# /admin/) so the HIT cannot pass for free on an unmatched-location redirect.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /admin/x", "GET /admin/x",
 "GET /api/x",   "GET /api/x",
 "GET /adminx",  "GET /adminx"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 3: /admin/ and /api/ themselves (exact directory root) bypass too
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /admin/", "GET /admin/",
 "GET /api/",   "GET /api/"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 4: SEGMENT BOUNDARY -- /login.phpXX must CACHE
# "/login.php" is slash-less, so the boundary branch of
# ngx_http_cache_turbo_uri_prefix() is LIVE. The byte after the needle here
# is 'X', not '/' or '.' and not end-of-URI, so this is a different path
# segment that merely shares the prefix and must cache. Served under the
# real /login.php location so the HIT cannot pass for free on an implicit
# 404.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /login.phpXX", "GET /login.phpXX"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 5: the two positive boundary arms still bypass
# "/login.php/extra" ('/' continuation) and "/login.php.bak" ('.'
# continuation) are both inside the matched subtree per the boundary check.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /login.php/extra", "GET /login.php/extra",
 "GET /login.php.bak",   "GET /login.php.bak"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 6: each predicate bypasses independently, under two install prefixes
# The five predicate rows match by SUFFIX, so both the common "MANTIS"
# prefix and an arbitrary install-chosen prefix ("myinstall") must both
# bypass on the same suffix. This is the load-bearing suffix-match proof.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers eval
["Cookie: MANTIS_STRING_COOKIE=abc123",
 "Cookie: MANTIS_STRING_COOKIE=abc123",
 "Cookie: myinstall_STRING_COOKIE=abc123",
 "Cookie: myinstall_STRING_COOKIE=abc123",
 "Cookie: MANTIS_PROJECT_COOKIE=3",
 "Cookie: MANTIS_PROJECT_COOKIE=3",
 "Cookie: MANTIS_VIEW_ALL_COOKIE=1",
 "Cookie: MANTIS_VIEW_ALL_COOKIE=1",
 "Cookie: MANTIS_BUG_LIST_COOKIE=42",
 "Cookie: MANTIS_BUG_LIST_COOKIE=42",
 "Cookie: MANTIS_collapse_settings=1",
 "Cookie: MANTIS_collapse_settings=1"]
--- request eval
["GET /mantisbt/view-a", "GET /mantisbt/view-a",
 "GET /mantisbt/view-b", "GET /mantisbt/view-b",
 "GET /mantisbt/view-c", "GET /mantisbt/view-c",
 "GET /mantisbt/view-d", "GET /mantisbt/view-d",
 "GET /mantisbt/view-e", "GET /mantisbt/view-e",
 "GET /mantisbt/view-f", "GET /mantisbt/view-f"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200]



=== TEST 7: NONEMPTY -- an EMPTY predicate cookie value does NOT bypass
# The opposite direction from punbb.t TEST 8/smf.t TEST 9: this preset's
# predicates use CVOP_NONEMPTY, not presence-only, so a cookie present with
# no value must still HIT.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: MANTIS_STRING_COOKIE=
--- request eval
["GET /mantisbt/view-empty", "GET /mantisbt/view-empty"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 7b: a BARE valueless predicate cookie (no '=') still bypasses
# The neighbouring edge to TEST 7, and the opposite verdict. TEST 7 pins that
# an EMPTY value does not bypass under CVOP_NONEMPTY; a BARE cookie carries no
# readable value at all, so the predicate engine cannot apply NONEMPTY to it
# and fails closed to bypass rather than guessing the value is empty.
#
# ci/t/presets/spip.t TEST 9 pins exactly this for the other NONEMPTY preset.
# MantisBT uses the same operator, so the two files must agree -- without this
# block the boundary between "empty" and "absent" was asserted on one side only.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: MANTIS_STRING_COOKIE
--- request eval
["GET /mantisbt/view-bare", "GET /mantisbt/view-bare"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]

=== TEST 8: the PHPSESSID cookie bypasses -- lazily-started native session
# Mantis form tokens lazily start a native PHP session for anonymous form
# pages, so PHPSESSID is included in ct_mantisbt_cookies[] alongside the
# symbolic predicates.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: PHPSESSID=abc123def456
--- request eval
["GET /mantisbt/view-sess", "GET /mantisbt/view-sess"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 9: SCAN TERMINATION -- a leading non-matching cookie does not mask the match
# A non-matching (empty-valued, unrelated-name) cookie sent first must not
# end the cookie scan before the real predicate cookie is reached.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: unrelated=; MANTIS_PROJECT_COOKIE=3
--- request eval
["GET /mantisbt/view-twin", "GET /mantisbt/view-twin"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 10: a request with no cookie at all still caches (repeat-HIT)
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /mantisbt/view-nocookie", "GET /mantisbt/view-nocookie"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 11: an unrelated guest cookie does NOT bypass
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: some_other_cookie=xyz
--- request eval
["GET /mantisbt/view-guest", "GET /mantisbt/view-guest"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 12: the MantisBT predicate cookie under /gen/ (wordpress) still HITs
# wordpress has its own cookie list and the mantisbt predicate rows do not
# leak across backends.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: MANTIS_STRING_COOKIE=abc123
--- request eval
["GET /gen/view-iso", "GET /gen/view-iso"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
