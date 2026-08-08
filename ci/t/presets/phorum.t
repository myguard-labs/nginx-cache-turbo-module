# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Phorum preset (docs/phorum.md). Ported from three tests in
# ci/tools/test_runtime.py, all deleted by this port:
# test_phorum_admin_session_cookie(), test_phorum_uri_rules_anchor_at_root(),
# and the phorum half of test_punbb_phorum_uri_rules() -- the punbb half of
# that shared test was already ported in punbb.t (#223); this cycle's port
# retires the whole function, its OK: string fragment, and the punbb-only
# fixtures (punbb_root_locs, location /punbb/) that only it used.
#
# THE COOKIE RULE IS PRESENCE-ONLY, AND SAFELY SO -- THE INVERSE TRAP
# ------------------------------------------------------------------------
# Verbatim from the ct_phorum_cookies[] header comment in src, because it
# names why this preset does NOT need the phpBB/SMF/PunBB value-predicate
# workaround:
#
#   Fixed, version-pinned literal session-cookie constants (phorum_session_v5,
#   phorum_session_st, phorum_admin_session -- PHP constants in
#   include/api/user.php, not per-install hashes or admin-configurable
#   prefixes) written ONLY by phorum_api_user_session_create(), which is
#   called ONLY from a successful login -- never for anonymous page
#   rendering. This is the inverse of the XenForo/Discourse/phpBB/Flarum
#   trap: presence alone is a safe, sufficient signal because guests never
#   receive any of these three cookies. No value predicate needed.
#
# `phorum_tmp_cookie` is a guest-received cookie-support PROBE with no
# identity value (destroyed once logged in) -- deliberately absent from the
# list; matching it would be a pure hit-rate loss for zero safety gain.
# TEST 6 pins it as a negative control. The row shipped as
# `phorum_admin_session_v5` once (a stale suffix -- PHORUM_SESSION_ADMIN
# carries no _v5), which never matched a real admin session cookie; TEST 5
# is the regression pin for the corrected literal.
#
# THE URI LIST, AND WHY /file.php MATTERS MOST
# ------------------------------------------------------------------------
# Verbatim from the ct_phorum_uris[] header comment in src:
#
#   "/file.php" is the row that matters most and was missing: it is the
#   ATTACHMENT DOWNLOAD script, and it authorises per request through the
#   file_storage API (a file attached to a private-forum message is refused
#   to anyone without read access to that forum). Serving it from the cache
#   hands the first requester's attachment body to every later requester of
#   the same file id, permission check skipped -- the same shape as the
#   phpBB download/file.php hazard.
#
# TEST 4 is the member LEAK GUARD for exactly this: /file.php must bypass,
# twice, with no cookie present at all -- the leak is per-URI, not
# cookie-gated. "/post.php" is kept even though Phorum 5 replaced it with
# posting.php: the file still ships as a stub whose body is a die() that
# overwrites the 5.0 script on upgrade so spammers cannot POST to it.
#
# ct_phorum_args[] is { NULL } and the preset row carries NULL in
# cookie_preds, so this file has no arg leg and no predicate leg. No row is
# a prefix of another row (admin.php/login.php/register.php/pm.php/
# posting.php/post.php/moderation.php/control.php/ajax.php/report.php/
# follow.php/file.php -- checked pairwise), so the #222 prefix-row rule does
# not apply here.
#
# key_cookies IS non-NULL: `list_style` (a presentation variant -- forum
# thread/flat/tree display, shared by everyone on that setting, not an
# identity signal). TESTS 7-9 cover the value-keying leg the way mybb.t
# TESTS 12/14 do: same value hits its own entry, different values do not
# collide, and an exact-name match folds nothing when the cookie carries an
# install-side prefix (a known, documented limitation, not a bug -- the safe
# failure direction, same as mybb.t TEST 14).
#
# "/admin.php" IS SLASH-LESS -- THE SEGMENT-TERMINATION BRANCH IS LIVE HERE
# ------------------------------------------------------------------------
# Same shape as punbb.t's "/login.php". Every phorum URI row is a bare
# .php script name with no trailing slash, so the byte after the needle
# must be checked. TEST 2 is the segment-termination oracle: "/admin.phpZZ"
# continues with 'Z', neither a boundary byte nor EOF, and must CACHE. TEST 3
# covers the two positive boundary arms ("/admin.php/extra" and
# "/admin.php.bak") that DO bypass. This is also the regression pin for
# test_phorum_uri_rules_anchor_at_root(): the row once shipped without a
# leading slash ("admin.php"), which can never match r->uri (always
# byte-0 '/'), so every phorum route stayed cacheable.
#
# THE VACUOUS URI TEST TRAP
# ------------------------------------------------------------------------
# uri_prefix() is byte-0 anchored, so a URI test served under a DIFFERENT
# location prefix (e.g. "/phorum/admin.php") never reaches the rule at all
# and would pass with the row deleted. TEST 1 puts every URI arm at the ROOT
# path; TEST 11 is the explicit negative proving "/phorum/admin.php" HITs
# precisely because the rule never fires off byte 0.
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

# Root-anchored prefix locations for every URI row. /phorum/ carries the
# path-independent cookie/key-cookie cases and the byte-0 vacuity control.
# /gen/ is the isolation control -- a DIFFERENT preset.
our $Config = ct_config(
    { path => '/admin.php',      backend => 'phorum' },
    { path => '/login.php',      backend => 'phorum' },
    { path => '/register.php',   backend => 'phorum' },
    { path => '/pm.php',         backend => 'phorum' },
    { path => '/posting.php',    backend => 'phorum' },
    { path => '/post.php',       backend => 'phorum' },
    { path => '/moderation.php', backend => 'phorum' },
    { path => '/control.php',    backend => 'phorum' },
    { path => '/ajax.php',       backend => 'phorum' },
    { path => '/report.php',     backend => 'phorum' },
    { path => '/follow.php',     backend => 'phorum' },
    { path => '/file.php',       backend => 'phorum' },
    { path => '/phorum/',        backend => 'phorum' },
    { path => '/gen/',           backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: every URI row bypasses at the root, with no cookie
# The full ct_phorum_uris[] table, each on its own path so a shared key
# cannot mask a missing row.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /admin.php",      "GET /admin.php",
 "GET /login.php",      "GET /login.php",
 "GET /register.php",   "GET /register.php",
 "GET /pm.php",         "GET /pm.php",
 "GET /posting.php",    "GET /posting.php",
 "GET /post.php",       "GET /post.php",
 "GET /moderation.php", "GET /moderation.php",
 "GET /control.php",    "GET /control.php",
 "GET /ajax.php",       "GET /ajax.php",
 "GET /report.php",     "GET /report.php",
 "GET /follow.php",     "GET /follow.php",
 "GET /file.php",       "GET /file.php"]
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



=== TEST 2: SEGMENT BOUNDARY -- /admin.phpZZ must CACHE
# "/admin.php" is slash-less, so the boundary branch of
# ngx_http_cache_turbo_uri_prefix() is LIVE. The byte after the needle here
# is 'Z', not '/' or '.' and not end-of-URI, so this is a different path
# segment that merely shares the prefix and must cache. Served under the
# real /admin.php location so the HIT cannot pass for free on an implicit
# 404. This is also the regression pin for test_phorum_uri_rules_anchor_at_
# root(): the row once shipped without a leading slash, which can never
# match r->uri at all.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /admin.phpZZ", "GET /admin.phpZZ"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 3: the two positive boundary arms still bypass
# "/admin.php/extra" ('/' continuation) and "/admin.php.bak" ('.'
# continuation) are both inside the matched subtree per the boundary check.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /admin.php/extra", "GET /admin.php/extra",
 "GET /admin.php.bak",   "GET /admin.php.bak"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 4: member LEAK GUARD -- /file.php bypasses with NO cookie present
# Phorum's permission-checked attachment download. It authorises per
# request through the file_storage API; caching it replays one member's
# attachment to every later requester of the same file id, permission check
# skipped. The leak is per-URI, not cookie-gated, so this is asserted with
# no Cookie header at all -- ported from test_punbb_phorum_uri_rules()'s
# phorum half.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /file.php?file=7", "GET /file.php?file=7"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 5: each of the three real session cookies bypasses
# phorum_session_v5, phorum_session_st, phorum_admin_session -- fixed PHP
# constants written only by phorum_api_user_session_create() on a successful
# login. Regression pin for the stale `phorum_admin_session_v5` literal
# (PHORUM_SESSION_ADMIN carries no _v5 suffix).
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers eval
["Cookie: phorum_session_v5=42:deadbeef",
 "Cookie: phorum_session_v5=42:deadbeef",
 "Cookie: phorum_session_st=42:cafebabe",
 "Cookie: phorum_session_st=42:cafebabe",
 "Cookie: phorum_admin_session=42:deadbeef",
 "Cookie: phorum_admin_session=42:deadbeef"]
--- request eval
["GET /phorum/read-a", "GET /phorum/read-a",
 "GET /phorum/read-b", "GET /phorum/read-b",
 "GET /phorum/read-c", "GET /phorum/read-c"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 6: phorum_tmp_cookie -- the guest-issued probe -- does NOT bypass
# A cookie-support PROBE with no identity value, destroyed once logged in.
# Matching it would be a pure hit-rate loss for zero safety gain, so it is
# deliberately absent from ct_phorum_cookies[].
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: phorum_tmp_cookie=1
--- request eval
["GET /phorum/read-guest", "GET /phorum/read-guest"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 7: list_style is VALUE-KEYED, and each value hits its own entry
# The sole key_cookies row -- a presentation variant (thread/flat/tree
# display), shared by everyone on that setting, so it must cache, repeat-hit
# its OWN entry, and NOT collide with a different value. Same shape as
# mybb.t TEST 12.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /phorum/variant-style", "GET /phorum/variant-style", "GET /phorum/variant-style"]
--- more_headers eval
["Cookie: list_style=threaded",
 "Cookie: list_style=threaded",
 "Cookie: list_style=flat"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}, qq{X-Cache: }]
--- response_body_like eval
[qr/list_style=threaded/, qr/list_style=threaded/, qr/list_style=flat/]
--- error_code eval
[200, 200, 200]



=== TEST 8: no list_style cookie -- the anonymous entry is its own bucket
# A cookie-less request must not collide with either keyed value from TEST
# 7 -- it warms and repeat-hits its own entry.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /phorum/no-style", "GET /phorum/no-style"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 9: list_style is matched EXACTLY -- a prefixed cookie folds NOTHING
# THE DELIBERATE ASYMMETRY, same shape as mybb.t TEST 14. On an install
# behind a theme/cookie-prefix proxy the wire name is `<prefix>list_style`;
# the key match is not a suffix match, so it folds nothing and both values
# land on ONE bucket -- request 2 HITs the entry stored for request 1 even
# though its style differs. A known, documented limitation (the safe
# direction: hit quality, not bucket selection), remedy is
# `cache_turbo_key_cookie <prefix>list_style;`.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /phorum/prefixed-key", "GET /phorum/prefixed-key"]
--- more_headers eval
["Cookie: myboard_list_style=threaded",
 "Cookie: myboard_list_style=flat"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 10: an unrelated guest cookie does NOT bypass
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: PHPSESSID=abc
--- request eval
["GET /phorum/topic-guest", "GET /phorum/topic-guest"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 11: THE VACUOUS URI TEST -- /phorum/admin.php HITs, not byte-0
# uri_prefix() is byte-0 anchored, so a URI test served under a location
# whose path is NOT the root never reaches the rule. This proves a URI arm
# sent under /phorum/ would pass for free even with the row deleted --
# exactly why every URI arm in TEST 1 is sent at the true root instead.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /phorum/admin.php", "GET /phorum/admin.php"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 12: the phorum session cookie under /gen/ (wordpress backend) still HITs
# Isolation control. wordpress has its own cookie list and the phorum rows
# do not leak across backends.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: phorum_session_v5=42:deadbeef
--- request eval
["GET /gen/topic-iso", "GET /gen/topic-iso"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
