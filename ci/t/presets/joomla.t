# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Joomla preset (docs/joomla.md). Ported from test_joomla_preset() in
# ci/tools/test_runtime.py.
#
# One cookie, and it is a PARTIAL guard -- read the caveat.
#
# `joomla_remember_me_` is a real fixed prefix ('joomla_remember_me_' .
# UserHelper::getShortHashedUserAgent()), set only for an authenticated user and
# cleared on logout. The per-install part is the SUFFIX, so the prefix is
# matchable -- this is the one Joomla cookie that passes both tests.
#
# WHAT IT DOES NOT COVER, and this is the important half: it is only present for
# users who ticked "Remember Me". A normally-logged-in frontend user carries only
# the SESSION cookie, whose NAME is md5($secret . $session_name) -- a per-install
# hash with no fixed substring anywhere in it. That user is invisible to this
# matcher. So joomla_remember_me_ raises the floor; it does not make the preset
# safe on its own.
#
# The real guard for a logged-in Joomla user therefore remains Joomla's own
# Cache-Control (core's page cache plugin itself gates on
# !$app->getIdentity()->guest), plus the /administrator/ URI rule. An operator
# running a site with frontend logins MUST add their own cache_turbo_bypass on
# their install's session-cookie name -- docs/joomla.md shows how to find it.
# Do not read the presence of a cookie rule here as "joomla is now handled".
#
# NO ARGS, NO PREDICATES, NO KEY COOKIES
# ---------------------------------------
# ct_joomla_args[] is empty and the preset's table row carries NULL for both
# cookie_preds and key_cookies (see ngx_http_cache_turbo_presets[] in
# src/ngx_http_cache_turbo_module.c). Only the cookie and URI legs below apply;
# there is no arg-rule leg, no value-predicate leg and no key-cookie leg to test
# here.
#
# THE URI NEEDLE IS ALREADY SLASH-TERMINATED -- NO BOUNDARY-BYTE LEG TO TEST
# ----------------------------------------------------------------------------
# ct_joomla_uris[] holds one row, "/administrator/", which already ends in '/'.
# ngx_http_cache_turbo_uri_prefix() takes the "carries its own segment
# terminator" branch for such a needle and returns on the ngx_strncmp prefix
# alone -- the boundary-byte check ('/'/'.', used for slash-less needles like
# "/panel") is never reached for this preset. TEST 2b therefore verifies byte-0
# prefix anchoring, not segment-termination; there is no engine-mutation on the
# boundary-byte branch that can turn it red for Joomla specifically (confirmed:
# deleting that branch entirely left every joomla.t test green).
#
# THE COOKIE RULE IS A PLAIN SUBSTRING MATCH, NOT A NAME-SUFFIX PARSE
# ---------------------------------------------------------------------
# ct_joomla_cookies[] is evaluated by ngx_http_cache_turbo_cookie_has(), which is
# a raw ngx_strnstr() search for the needle ANYWHERE in the whole Cookie header
# value -- not the name/value-pair suffix parser phpBB's _u predicate uses. So
# TEST 3 (partial word match) and TEST 4 (needle spanning a NAME=VALUE boundary)
# both pass, because the matcher never looks for a '=' or a pair boundary at
# all. This is deliberate and documented at ngx_http_cache_turbo_cookie_has():
# "the login/session cookies carry dynamic suffixes, so a substring match on the
# distinctive prefix is the right test, not an exact-name lookup." Do not "fix"
# this into a name-anchored match; that is a different function
# (ngx_http_cache_turbo_cookie_pred) reserved for presets that need it.
#
# See ci/t/presets/xenforo.t for why every bypass case is fetched TWICE and why
# these are `--- request eval` arrays rather than `--- pipelined_requests`.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

# The preset's URI rule is a prefix anchored at byte 0, so /administrator/ must
# be a ROOT location. /jm/ carries the cookie cases, which are path-independent.
# /gen/ is the isolation control -- a DIFFERENT preset, proving the joomla rows
# are opt-in.
our $Config = ct_config(
    { path => '/administrator/', backend => 'joomla'    },
    { path => '/jm/',            backend => 'joomla'    },
    { path => '/gen/',           backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: /administrator/ bypasses on the URI rule
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /administrator/index.php", "GET /administrator/index.php"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 1a: the bare mount itself (no sub-path) bypasses too
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /administrator/", "GET /administrator/"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 2: the URI rule matches sub-routes under the mount
# ct_joomla_uris[] rows are prefix-anchored but segment-terminated: the needle
# "/administrator/" already ends in '/', so it is a plain byte-0 prefix and every
# sub-route under it matches.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /administrator/templates/foo", "GET /administrator/templates/foo"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 2a: the URI rule matches a sub-route carrying a query string too
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /administrator/index.php?option=com_login", "GET /administrator/index.php?option=com_login"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 2b: a merely-similar sibling path is NOT covered -- byte-0, not vacuous
# The KNOWN VACUOUS-TEST TRAP: the lookalike must be sent DIRECTLY at byte 0, not
# nested under the real prefix, or the test would still pass with the whole rule
# deleted. The needle here is "/administrator/" -- already SLASH-TERMINATED, so
# ngx_http_cache_turbo_uri_prefix() takes the "carries its own segment
# terminator" branch and never reaches the boundary-byte ('/'/'.') check at all
# (see the function's own comment). What this test therefore verifies is the
# byte-0 PREFIX itself: "/administratorX" is missing the needle's trailing '/'
# and so fails the ngx_strncmp before the boundary logic is ever consulted.
# "/jm/administratorX" additionally does not begin with "/administrator/" at
# position 0 -- it is a DIFFERENT route on a DIFFERENT mount -- and must NOT
# bypass, so the second fetch must HIT.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /jm/administratorX", "GET /jm/administratorX"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 3: joomla_remember_me_<hash> bypasses -- THE LEAK GUARD
# Set only for a user who ticked "Remember Me", cleared on logout. Without this
# rule the member's authenticated page is stored and served to strangers.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: joomla_remember_me_9f8e7d6c=abc123
--- request eval
["GET /jm/article-a", "GET /jm/article-a"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 3b: a DIFFERENT install's remember-me hash still bypasses
# The per-install suffix is arbitrary, so a second, unrelated hash must match
# the same fixed prefix just as the first one did.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: joomla_remember_me_00112233aabbccdd=zzz999
--- request eval
["GET /jm/article-a2", "GET /jm/article-a2"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 3c: an empty-value remember-me cookie still bypasses -- substring, not value-aware
# The matcher is a name substring only; it never inspects the value, so even an
# emptied/cleared-looking cookie whose NAME still carries the needle bypasses.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: joomla_remember_me_9f8e7d6c=
--- request eval
["GET /jm/article-a3", "GET /jm/article-a3"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 4: the match is a SUBSTRING anywhere in the header, not a name lookup
# ngx_http_cache_turbo_cookie_has() is ngx_strnstr() over the whole Cookie
# header value, so the needle also fires from inside an adjacent pair's VALUE,
# with no '=' or ';' boundary required. Pinning this (rather than assuming a
# name-anchored parse) is what stops a future "helpful" rewrite to the
# name/value predicate parser from being read as a no-op refactor.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: other=xxjoomla_remember_me_deadbeefxx
--- request eval
["GET /jm/article-substr", "GET /jm/article-substr"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 4b: the needle also fires with an unrelated cookie AHEAD of it in the header
# Same substring property, exercised from the other position: a first pair with
# an unrelated name, then the real remember-me cookie -- proving the scan is not
# short-circuited by whatever comes first.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: unrelated=1; joomla_remember_me_9f8e7d6c=abc123
--- request eval
["GET /jm/article-substr2", "GET /jm/article-substr2"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 4c: the needle sitting at the very END of the header still fires
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: a=1; b=2; joomla_remember_me_
--- request eval
["GET /jm/article-substr3", "GET /jm/article-substr3"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 5: THE PARTIAL-GUARD GAP -- the md5-named session cookie still caches
# THE GAP, asserted on purpose: a normally-logged-in frontend user (who did NOT
# tick "Remember Me") carries only the session cookie, whose NAME is
# md5($secret . $session_name) -- a per-install hash with no fixed substring.
# That user is INVISIBLE to this matcher, by construction, and the page still
# caches. This is a KNOWN limitation, not a regression -- if a future change
# makes this bypass, the preset got better and this assertion should be
# revisited deliberately, not deleted in passing.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: b1946ac92492d2347c6235b4d2611184=sessvalue
--- request eval
["GET /jm/article-b", "GET /jm/article-b"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 6: a cookieless visitor still caches -- the preset is not a blanket bypass
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /jm/article-c", "GET /jm/article-c"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 7: the joomla cookie rule does not leak into another backend's location
# /gen/ runs the wordpress preset. joomla_remember_me_ is not a wordpress
# signal, so the generic location must cache it -- proving the registry selects
# rows by preset bit rather than ORing every preset together.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: joomla_remember_me_9f8e7d6c=abc123
--- request eval
["GET /gen/topic", "GET /gen/topic"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
