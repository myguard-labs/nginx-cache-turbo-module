# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Discourse preset (docs/discourse.md). Ported from test_discourse_preset() in
# ci/tools/test_runtime.py, deleted by this port along with its `location
# /session` and `location /u/` fixtures. `location /dc/` is NOT removed: it is
# also the fixture test_preset_arg_scanner() uses for its PHP-key-mangling
# arms ("api.key"/"api username" folding to "api_key"/"api_username"), so it
# stays in test_runtime.py's config exactly as-is.
#
# `_t=`, THE AUTH TOKEN -- AND WHY THE TRAILING '=' MATTERS
# ------------------------------------------------------------------------
# Verbatim gist from the ct_discourse_cookies[] header comment in src:
#
#   `_t` is the auth token (lib/auth/default_current_user_provider.rb --
#   TOKEN_COOKIE), deleted outright for anonymous requests -- the exact test
#   Discourse's own anon cache uses. `_forum_session` is the Rails session
#   cookie and is issued to EVERY visitor including guests, so it is the
#   xf_session trap wearing a different hat: bypassing on it would drop all
#   guest traffic out of the cache. `theme_ids` / `forced_color_mode` are
#   presentation variants Discourse folds into its own cache key, not a
#   bypass signal here.
#
#   The rule is "_t=", not "_t": a two-character substring would match
#   inside unrelated names and values (_gat, utm_term=...). The trailing
#   "=" pins it to a name/value boundary. It can still over-match a cookie
#   literally named "<something>_t" (e.g. "list_t"), which costs a
#   needless bypass but never leaks -- a substring matcher cannot do
#   better, and "; _t=" would miss _t as the FIRST cookie in the header.
#
# `/u/` (public user profiles) IS DELIBERATELY ABSENT from ct_discourse_uris[]:
# profiles are anonymous-identical and Discourse's own anon cache caches them,
# so bypassing was pure hit-rate loss with no safety gain -- TEST 9 pins the
# positive (public profile caches).
#
# THE ROUTE IS `/drafts`, PLURAL -- NOT `/draft`
# ------------------------------------------------------------------------
# `resources :drafts` in config/routes.rb. An earlier `/draft` (singular)
# matched only via the old boundary-less prefix test and stops matching
# `/drafts.json` under the segment-boundary matcher, so it is corrected here.
#
# MIXED NEEDLE SHAPES -- THE SEGMENT-TERMINATION BRANCH IS LIVE
# ------------------------------------------------------------------------
# ct_discourse_uris[] mixes slash-terminated needles ("/auth/", "/my/",
# "/message-bus/", "/presence/" -- these carry their own segment terminator,
# so ngx_http_cache_turbo_uri_prefix()'s boundary branch short-circuits) with
# slash-less needles ("/admin", "/session", "/login", "/logout", "/signup",
# "/drafts", "/notifications", "/user_actions"). Because at least one needle
# is slash-less, the boundary branch is reachable and must be exercised: TEST
# 2 is the segment-termination oracle ("/adminXtra" must CACHE, since 'X' is
# neither a boundary byte nor end-of-URI), TEST 3 covers the two positive
# boundary arms that DO bypass.
#
# No row is a byte-prefix of another: "/login" and "/logout" diverge at byte
# 4 ("i" vs "o"), and none of the other slash-less rows extend one another
# either (checked pairwise across the full 12-row table), so the #222
# prefix-row rule does not add a case here.
#
# THIS PRESET HAS AN ARG TIER -- ct_discourse_args[] = { "api_key",
# "api_username", NULL }. The /dcarg/ location below overrides the suite
# default key to `$is_args$args` so a query-arg case is not silently masked
# by a path-only key (TEST 11: repeat traffic for the SAME ?api_key= value
# must stay bypassed rather than looking like an ordinary cached entry).
# preds and key_cookies are both NULL in the preset row, so there is no
# predicate leg and no value-keying leg here.
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

# Root-anchored prefix locations for every URI row. /disc/ carries the
# path-independent cookie cases. /dcarg/ carries the arg cases, keyed on
# $is_args$args so distinct ?api_key= values land on distinct entries.
# /gen/ is the isolation control -- a DIFFERENT preset.
our $Config = ct_config(
    { path => '/admin',          backend => 'discourse' },
    { path => '/session',        backend => 'discourse' },
    { path => '/auth/',          backend => 'discourse' },
    { path => '/login',          backend => 'discourse' },
    { path => '/logout',         backend => 'discourse' },
    { path => '/signup',         backend => 'discourse' },
    { path => '/my/',            backend => 'discourse' },
    { path => '/message-bus/',   backend => 'discourse' },
    { path => '/drafts',         backend => 'discourse' },
    { path => '/presence/',      backend => 'discourse' },
    { path => '/notifications',  backend => 'discourse' },
    { path => '/user_actions',   backend => 'discourse' },
    { path => '/disc/',          backend => 'discourse' },
    { path => '/u/',             backend => 'discourse' },
    { path => '/draft',          backend => 'discourse' },
    { path => '/dcarg/',         backend => 'discourse',
      extra => 'cache_turbo_key $is_args$args;' },
    { path => '/gen/',           backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: every URI row bypasses at the root, with no cookie
# The full ct_discourse_uris[] table, each on its own path so a shared key
# cannot mask a missing row.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /admin",         "GET /admin",
 "GET /session",       "GET /session",
 "GET /auth/step1",    "GET /auth/step1",
 "GET /login",         "GET /login",
 "GET /logout",        "GET /logout",
 "GET /signup",        "GET /signup",
 "GET /my/preferences", "GET /my/preferences",
 "GET /message-bus/x",  "GET /message-bus/x",
 "GET /drafts",         "GET /drafts",
 "GET /presence/get",   "GET /presence/get",
 "GET /notifications",  "GET /notifications",
 "GET /user_actions",   "GET /user_actions"]
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



=== TEST 2: SEGMENT BOUNDARY -- /adminXtra must CACHE
# "/admin" is slash-less, so the boundary branch of
# ngx_http_cache_turbo_uri_prefix() is LIVE. The byte after the needle here
# is 'X', not '/' or '.' and not end-of-URI, so this is a different path
# segment that merely shares the prefix and must cache. Served under the
# real /admin location so the HIT cannot pass for free on an implicit 404.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /adminXtra", "GET /adminXtra"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 3: the two positive boundary arms still bypass
# "/admin/extra" ('/' continuation) and "/admin.bak" ('.' continuation) are
# both inside the matched subtree per the boundary check.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /admin/extra", "GET /admin/extra",
 "GET /admin.bak",   "GET /admin.bak"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 4: /drafts is PLURAL -- /draft alone does not bypass
# resources :drafts in config/routes.rb. An earlier singular "/draft" only
# ever matched via the old boundary-less prefix test; under the real
# segment-boundary matcher "/draft" (six characters) is SHORTER than the
# needle "/drafts" (seven characters), so ngx_http_cache_turbo_uri_prefix()'s
# own `uri->len < l` check rejects it outright and it must stay cacheable.
# Served under its own dedicated root location (a `cache_turbo_backend
# discourse` location whose path happens to be exactly "/draft") so a HIT
# proves the module's own row scan found no match here, not that routing
# never reached the discourse rule at all.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /draft", "GET /draft"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 5: "_t=" -- the real auth token -- MUST bypass
# Written by lib/auth/default_current_user_provider.rb (TOKEN_COOKIE),
# deleted outright for anonymous requests. Present alongside an unrelated
# guest cookie the way a real logged-in browser would send it.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: theme_ids=2; _t=abc123deadbeef
--- request eval
["GET /disc/topic-a", "GET /disc/topic-a"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 6: guest _forum_session does NOT bypass
# Rails session cookie, issued to EVERY visitor including guests -- the
# xf_session trap wearing a different hat. Bypassing on it would drop all
# guest traffic out of the cache.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: _forum_session=guestsess123
--- request eval
["GET /disc/topic-b", "GET /disc/topic-b"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 7: theme_ids / forced_color_mode variant cookies do NOT bypass
# Presentation variants Discourse folds into its own cache key, not a
# bypass signal on this tier.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: theme_ids=2; forced_color_mode=dark
--- request eval
["GET /disc/topic-c", "GET /disc/topic-c"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 8: a cookie merely NAMED "<something>_t" over-matches by design
# The "_t=" rule can match inside a cookie literally named e.g. "list_t"
# (any name ending "_t" followed by "="). That costs a needless bypass but
# never leaks -- documented here rather than silently changed, since a
# substring matcher on a two-character token cannot do better.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: list_t=whatever
--- request eval
["GET /disc/topic-overmatch", "GET /disc/topic-overmatch"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 9: /u/ public profile is NOT a bypass row -- it caches
# Deliberately absent from ct_discourse_uris[]: profiles are anonymous-
# identical and Discourse's own anon cache already caches them, so a bypass
# here was pure hit-rate loss with no safety gain. Served under a genuine
# `cache_turbo_backend discourse` location so a HIT proves the absence is a
# real registry decision, not an accident of a location the preset never
# reaches.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /u/someone", "GET /u/someone"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 10: ?api_key= and ?api_username= both bypass; an unrelated arg does not
# ct_discourse_args[] = { "api_key", "api_username", NULL }.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /dcarg/topic-d?api_key=deadbeef",      "GET /dcarg/topic-d?api_key=deadbeef",
 "GET /dcarg/topic-e?api_username=admin",    "GET /dcarg/topic-e?api_username=admin",
 "GET /dcarg/topic-f?sort=latest",           "GET /dcarg/topic-f?sort=latest"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 11: same ?api_key= value revisited is still bypass, never a false HIT
# $is_args$args is in the key on /dcarg/ specifically so a bypass row is not
# quietly masked by a path-only key that would otherwise make repeat traffic
# for the SAME arg value look like an ordinary cacheable entry once bypass
# logic is disturbed. Both fetches for the identical query string must still
# show no X-Cache at all.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /dcarg/topic-g?api_key=repeat", "GET /dcarg/topic-g?api_key=repeat",
 "GET /dcarg/topic-g?api_key=repeat", "GET /dcarg/topic-g?api_key=repeat"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 12: an unrelated cookie does NOT bypass
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: unrelated_tracker=xyz
--- request eval
["GET /disc/topic-guest", "GET /disc/topic-guest"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 13: the "_t=" cookie under /gen/ (wordpress backend) still HITs
# Isolation control. wordpress has its own cookie list and the discourse
# rows do not leak across backends.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: _t=abc123deadbeef
--- request eval
["GET /gen/topic-iso", "GET /gen/topic-iso"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
