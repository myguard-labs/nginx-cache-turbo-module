# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Dotclear preset (docs/dotclear.md).
#
# PROVENANCE — Verbatim from ct_dotclear_cookies[] header comment in src:
#
#   Dotclear. The public frontend does not start the configured PHP session by
#   default; the backend does. `dcxd` is DC_SESSION_NAME's stock value and also
#   prefixes per-blog frontend sessions. dc_admin is the fixed remember-cookie,
#   while dc_passwd grants access to password-protected posts/pages. Preview
#   routes expose unpublished content on the public host. DC_SESSION_NAME and
#   DC_ADMIN_URL are configurable, so non-default deployments need matching
#   operator rules (see docs/dotclear.md).
#
# THE COOKIE RULE IS PRESENCE-ONLY
# ---------------------------------
# All three cookies are presence-only: dcxd is DC_SESSION_NAME's stock value and
# prefixes per-blog frontend sessions; dc_admin and dc_passwd are fixed
# remember-cookies written only by authenticated actions. No value predicates
# are needed -- guests never receive any of these three.
#
# IMPORTANT: dcxd HAS NO TRAILING '=' WHILE dc_admin AND dc_passwd DO
# -----------------------------------------------------------------------
# This is load-bearing. `dcxd` is a bare session id, while `dc_admin=` and
# `dc_passwd=` carry values. All three are matched via
# ngx_http_cache_turbo_cookie_has() -- a plain SUBSTRING search over the raw
# Cookie header value, not a suffix-of-name match -- so "dcxd" bypasses
# whenever that string appears anywhere in the header, including inside the
# per-blog spelling "dcxd_myblog" (a dynamic SUFFIX on the cookie NAME, which
# the substring search matches for free). "dc_admin=" and "dc_passwd="
# likewise match whenever those exact byte sequences (name-then-equals)
# appear anywhere, including under an operator-added prefix like
# "myprefix_dc_admin=". TEST 4 pins the per-blog spellings.
#
# THE URI LIST -- ALL THREE ARE SEPARATE AND SEGMENT-TERMINATED
# ---------------------------------------------------------------
# /admin -- the main backend; /preview -- preview of unpublished posts; /pagespreview
# -- preview of unpublished pages. All three are segment-terminated (the byte
# after the needle must be '/', '.' or end-of-URI). Neither /preview nor
# /pagespreview is a prefix of the other. TEST 2 covers segment termination;
# TEST 3 is the explicit negative proving `/administrator` does NOT bypass.
#
# ct_dotclear_args[] is { NULL } and the preset row carries NULL in both
# cookie_preds and key_cookies, so this file has no arg leg, no predicate leg
# and no value-keying leg.
#
# THE VACUOUS URI TEST TRAP
# --------------------------
# uri_prefix() is byte-0 anchored, so a URI test served under a DIFFERENT
# location prefix (e.g. "/dotclear/admin") never reaches the rule at all and
# would pass with the row deleted. TEST 8 puts every URI arm at the ROOT path;
# TEST 11 is the explicit negative proving "/dotclear/admin" HITs precisely
# because the rule never fires off byte 0.
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

# Root-anchored prefix locations for every URI row. /dotclear/ carries the
# path-independent cookie cases and the byte-0 vacuity control. /gen/ is the
# isolation control -- a DIFFERENT preset.
our $Config = ct_config(
    { path => '/admin',         backend => 'dotclear' },
    { path => '/preview',       backend => 'dotclear' },
    { path => '/pagespreview',  backend => 'dotclear' },
    { path => '/dotclear/',     backend => 'dotclear' },
    { path => '/gen/',          backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: every URI row bypasses at the root, with no cookie
# The full ct_dotclear_uris[] table, each on its own path so a shared key cannot
# mask a missing row.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /admin",         "GET /admin",
 "GET /preview",       "GET /preview",
 "GET /pagespreview",  "GET /pagespreview"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 2: SEGMENT TERMINATION -- /adminZZ must CACHE
# All three URI rows are segment-terminated, so the byte after the needle must
# be '/', '.' or end-of-URI. The byte after "/admin" here is 'Z', not a
# boundary, so this is a different path segment that merely shares the prefix
# and must cache. Served under the real /admin location so the HIT cannot pass
# for free on an implicit 404.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /adminZZ", "GET /adminZZ"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 3: /administrator is NOT a prefix match -- must CACHE
# A negative control. "/admin" is one row, "/pagespreview" is another. Neither
# is a prefix of "/administrator" (different path segment -- the byte after
# "admin" is 'i', not a boundary), and the row endpoint is not "/administratorX"
# for any X. This must cache.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /administrator", "GET /administrator"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 4: dcxd (no '=') and per-blog spellings bypass
# dcxd prefixes per-blog frontend sessions. A session for blog "myblog" is sent
# as "dcxd_myblog". The substring search over the raw Cookie header matches
# "dcxd" wherever it appears, so both the bare "dcxd" and the per-blog
# "dcxd_myblog" spelling bypass. (Note: "dcxd" has no trailing '=', unlike
# dc_admin= and dc_passwd=.)
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers eval
["Cookie: dcxd=session",
 "Cookie: dcxd=session",
 "Cookie: dcxd_blog=session",
 "Cookie: dcxd_blog=session"]
--- request eval
["GET /dotclear/dcxd-bare",     "GET /dotclear/dcxd-bare",
 "GET /dotclear/dcxd-per-blog", "GET /dotclear/dcxd-per-blog"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 5: dc_admin= (with '=') and dc_passwd= bypass
# The fixed remember-cookies. dc_admin grants backend access; dc_passwd grants
# access to password-protected posts/pages. Both include the trailing '='.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers eval
["Cookie: dc_admin=remembered",
 "Cookie: dc_admin=remembered",
 "Cookie: dc_passwd=protected-post",
 "Cookie: dc_passwd=protected-post"]
--- request eval
["GET /dotclear/admin-cookie",  "GET /dotclear/admin-cookie",
 "GET /dotclear/passwd-cookie", "GET /dotclear/passwd-cookie"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 6: a leading non-matching cookie, then a matching one -- bypasses
# A bypass and a first-time MISS both lack X-Cache. The cookie scan must not
# end at the first non-matching cookie. This tests that the dcxd cookie is
# found even though an unrelated cookie precedes it.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: PHPSESSID=generic; dcxd=found
--- request eval
["GET /dotclear/scan-order", "GET /dotclear/scan-order"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 7: a dynamic prefix on the cookie name still bypasses
# The match is a raw substring search over the Cookie header, so a proxy- or
# theme-prefixed variant (e.g. "mysite_dcxd") is still a login signal and
# bypasses.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers eval
["Cookie: mysite_dcxd=session",
 "Cookie: mysite_dcxd=session",
 "Cookie: myprefix_dc_admin=remembered",
 "Cookie: myprefix_dc_admin=remembered"]
--- request eval
["GET /dotclear/dcxd-prefix",  "GET /dotclear/dcxd-prefix",
 "GET /dotclear/admin-prefix", "GET /dotclear/admin-prefix"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 8: empty cookie value -- bypasses (presence-only)
# No cookie_preds row exists for dotclear; the rule is presence-only. An empty
# value is still a bypass -- the fail-CLOSED direction, same as smf.t TEST 9.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: dcxd=
--- request eval
["GET /dotclear/empty-dcxd", "GET /dotclear/empty-dcxd"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 9: bare valueless cookie (no '=') -- bypasses (presence-only)
# An unreadable cookie must never be assumed a guest. Same shape as smf.t TEST
# 10.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: dcxd
--- request eval
["GET /dotclear/bare-dcxd", "GET /dotclear/bare-dcxd"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 10: a cookieless request caches
# No dotclear cookies present. The request must cache and repeat-hit its own
# entry.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /dotclear/public", "GET /dotclear/public"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 11: THE VACUOUS URI TEST -- /dotclear/admin HITs, not byte-0
# uri_prefix() is byte-0 anchored, so a URI test served under a location whose
# path is NOT the root never reaches the rule. This proves a URI arm sent under
# /dotclear/ would pass for free even with the row deleted -- which is exactly
# why every URI arm in TEST 1 is sent at the true root instead.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /dotclear/admin", "GET /dotclear/admin"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 12: the dotclear cookie under /gen/ (wordpress backend) still HITs
# Isolation control. wordpress has its own cookie list and the dotclear rows
# do not leak across backends.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: dcxd=session
--- request eval
["GET /gen/topic-iso", "GET /gen/topic-iso"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
