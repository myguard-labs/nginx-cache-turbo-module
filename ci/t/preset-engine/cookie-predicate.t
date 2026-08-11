# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Preset ENGINE test: the query-arg matcher must match on VALUE, not on the
# bare argument NAME. Ported from test_preset_arg_value_predicate() in
# ci/tools/test_runtime.py, which is DELETED by this port.
#
# This is a cross-cutting engine test, not a preset test: it lives in
# ci/t/preset-engine/, not ci/t/presets/. It rides on the smf preset only
# because smf is the plainest single-entry-script backend (see
# ci/t/presets/smf.t) -- the preset's own row coverage stays in that file.
#
# THE BUG THIS GUARDS
# --------------------
# Preset arg rows are written as `name=value` (e.g. "action=login"). The
# classifier originally looked each row up as a bare argument NAME, so
# "action=login" was searched for as an argument literally called
# "action=login" -- which never exists in a real query string -- and the
# login/PM/moderation routes stayed cacheable when they must not. Matching on
# the NAME alone is not the fix either: every row shares the argument name
# "action", so a name-only match would bypass the ENTIRE board on every
# request, silently switching the cache off. Both halves must be asserted:
# a listed `name=value` bypasses, and an unlisted VALUE on that same name
# still caches.
#
# See ci/t/presets/xenforo.t for why every bypass case below is fetched
# TWICE via `--- request eval` arrays: a bypass and a first-time MISS both
# come back with no X-Cache header, so a single fetch would pass with the
# rule removed entirely. Only a bypass keeps the header absent on the SECOND
# request -- an ordinary MISS would have been stored and would answer HIT.
#
# The /smf/ location keys on $request_uri (query string included), matching
# ci/tools/test_runtime.py's fixture: with the default $uri-only key, every
# query variant used below would collapse onto ONE cache entry and the
# per-query assertions would stop meaning anything.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

our $Config = ct_config(
    { path => '/smf/', backend => 'smf',
      extra => 'cache_turbo_key $request_uri;' },
);

run_tests();

__DATA__

=== TEST 1: a listed action= VALUE bypasses -- login, admin, pm
# Fetched twice per case, each on its own path/query so the entries cannot
# collide with each other.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /smf/index.php?action=login&t=0", "GET /smf/index.php?action=login&t=0",
 "GET /smf/index.php?action=admin&t=1", "GET /smf/index.php?action=admin&t=1",
 "GET /smf/index.php?action=pm&t=2",    "GET /smf/index.php?action=pm&t=2"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 2: an UNLISTED value on the SAME argument name still caches
# THE LOAD-BEARING NEGATIVE. Both rows share the argument NAME "action". If
# the matcher ever fell back to matching the bare name, this would flip to a
# bypass and the entire board would go uncacheable.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /smf/index.php?action=display", "GET /smf/index.php?action=display",
 "GET /smf/index.php?action=recent",  "GET /smf/index.php?action=recent"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]
