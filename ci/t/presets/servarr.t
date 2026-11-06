# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Servarr preset: Sonarr, Radarr, Lidarr (docs/servarr.md). A SAFETY preset --
# the apps serve no anonymous HTML, so its job is keeping the login cookie, the
# API key surface and the private routes out of the cache. The hazard it closes
# is the upstream `h`-arg rule: GET /initialize.json?h=x returns the API key
# with `Cache-Control: public, max-age=31536000` (TEST 3).
#
# Negative control: with the preset removed from the registry (or the conf name
# dropped) every bypass TEST goes red -- a bypass case then returns X-Cache: HIT
# on its second fetch.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

our $Config = ct_config(
    { path => '/api', backend => 'servarr' },
    { path => '/feed', backend => 'servarr' },
    { path => '/signalr', backend => 'servarr' },
    { path => '/initialize.json', backend => 'servarr' },
    { path => '/login', backend => 'servarr' },
    { path => '/logout', backend => 'servarr' },
    { path => '/loggedout', backend => 'servarr' },
    { path => '/logfile', backend => 'servarr' },
    { path => '/updatelogfile', backend => 'servarr' },
    { path => '/backup', backend => 'servarr' },
    { path => '/MediaCover', backend => 'servarr' },
    { path => '/MediaCoverProxy', backend => 'servarr' },
    { path => '/content/', backend => 'servarr' },
    { path => '/servarr/', backend => 'servarr' },
    { path => '/alias-sonarr/', backend => 'sonarr' },
    { path => '/alias-radarr/', backend => 'radarr' },
    { path => '/alias-lidarr/', backend => 'lidarr' },
    { path => '/gen/', backend => 'wordpress' },
    { path => '/WP-ADMIN/', backend => 'wordpress' },
    { path => '/API/', backend => 'servarr' },
    { path => '/APIX', backend => 'servarr' },
    { path => '/Initialize.json', backend => 'servarr' },
    { path => '/Feed/', backend => 'servarr' },
    { path => '/mediacover/', backend => 'servarr' },
    { path => '/SONARR/', backend => 'servarr',
      extra => 'cache_turbo_backend_prefix /sonarr/;' },
);

run_tests();

__DATA__


=== TEST 1: every URI row bypasses at the root, with no cookie
# The full ct_servarr_uris[] table, each on its own root path (the URI tier is
# byte-0 anchored, so a deeper location would pass with the row deleted).
# Every bypass case is fetched TWICE: a bypass and a first-time MISS both lack
# X-Cache (see ci/t/presets/discourse.t).
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /api", "GET /api",
 "GET /feed", "GET /feed",
 "GET /signalr", "GET /signalr",
 "GET /initialize.json", "GET /initialize.json",
 "GET /login", "GET /login",
 "GET /logout", "GET /logout",
 "GET /loggedout", "GET /loggedout",
 "GET /logfile", "GET /logfile",
 "GET /updatelogfile", "GET /updatelogfile",
 "GET /backup", "GET /backup",
 "GET /MediaCover", "GET /MediaCover",
 "GET /MediaCoverProxy", "GET /MediaCoverProxy"]
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
[200, 200,
 200, 200,
 200, 200,
 200, 200,
 200, 200,
 200, 200,
 200, 200,
 200, 200,
 200, 200,
 200, 200,
 200, 200,
 200, 200]


=== TEST 2: SEGMENT BOUNDARY -- /apiXtra caches, /api/v3/series and /api.json bypass
# "/api" is slash-less, so the boundary branch of ngx_http_cache_turbo_uri_prefix()
# is live: a different segment sharing the prefix caches, the two continuation
# bytes (/ and .) stay inside the subtree.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /apiXtra", "GET /apiXtra",
 "GET /api/v3/series", "GET /api/v3/series",
 "GET /api.json", "GET /api.json"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200,
 200, 200,
 200, 200]


=== TEST 3: THE VERIFIED HAZARD -- /initialize.json?h=x bypasses with NO cookie
# Upstream CacheableSpecification marks any request carrying an `h` arg as
# `public, max-age=31536000` BEFORE its /api and /initialize.json exclusions, so
# the API key in /initialize.json would be stored by an origin-honouring cache.
# The URI row keeps it out even without a login cookie (External auth, API
# clients). /api/v3/series?h=x is the same shape.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /initialize.json?h=x", "GET /initialize.json?h=x",
 "GET /api/v3/series?h=x", "GET /api/v3/series?h=x"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200,
 200, 200]


=== TEST 4: the <InstanceName>Auth login cookie bypasses
# Forms login issues <InstanceName>Auth (instance name operator-set, suffix
# fixed). The substring `Auth=` covers SonarrAuth, RadarrAuth and renamed
# instances alike; never issued to a guest.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: SonarrAuth=CfDJ8abc
--- request eval
["GET /servarr/series/1", "GET /servarr/series/1"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]


=== TEST 5: a renamed instance cookie (MyMediaAuth) bypasses
# Same row, a custom instance name.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: MyMediaAuth=xyz
--- request eval
["GET /servarr/movie/2", "GET /servarr/movie/2"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]


=== TEST 6: the v5 OIDC cookie bypasses
# `OIDC=` is the Sonarr v5 OIDC session cookie.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: SonarrOIDC=tok
--- request eval
["GET /servarr/movie/3", "GET /servarr/movie/3"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]


=== TEST 7: an unrelated cookie does NOT bypass
# Positive control: the cookie rows must not over-match.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: theme=dark
--- request eval
["GET /servarr/show/guest", "GET /servarr/show/guest"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]


=== TEST 8: credential args: apikey and access_token bypass
# API key arg and the SignalR access_token arg, on a path no URI row covers,
# so only the arg tier can be what bypasses.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /content/x?apikey=abc", "GET /content/x?apikey=abc",
 "GET /content/y?access_token=abc", "GET /content/y?access_token=abc"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200,
 200, 200]


=== TEST 9: the `h` arg is NOT a bypass: hashed static assets still HIT
# The whole point of leaving `h` out of ct_servarr_args[]: it is the only
# legitimate hit source (hashed js/css under /content/).
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /content/app.js?h=abc123", "GET /content/app.js?h=abc123"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]


=== TEST 10: THE VACUOUS URI TEST -- /servarr/api HITs, not byte-0
# Served under a non-root location the URI row never fires; proves TEST 1 uses
# the true root on purpose.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /servarr/api", "GET /servarr/api"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]


=== TEST 11: the sonarr / radarr / lidarr aliases arm the same preset
# Alias names map to the same bit. Cookie fired on each alias location.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: SonarrAuth=a
--- request eval
["GET /alias-sonarr/page", "GET /alias-sonarr/page"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]


=== TEST 12: radarr alias bypasses
# Radarr alias.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: RadarrAuth=a
--- request eval
["GET /alias-radarr/page", "GET /alias-radarr/page"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]


=== TEST 13: lidarr alias bypasses
# Lidarr alias.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: LidarrAuth=a
--- request eval
["GET /alias-lidarr/page", "GET /alias-lidarr/page"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]


=== TEST 14: isolation -- the Auth cookie under /gen/ (wordpress) still HITs
# Servarr rows must not leak into another preset.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: SonarrAuth=a
--- request eval
["GET /gen/topic-iso", "GET /gen/topic-iso"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]


=== TEST 15: CASE-FOLDED URI rows -- ASP.NET routes /API and /Initialize.json too
# Servarr (ASP.NET Core) routes paths and UsePathBase case-insensitively, and the
# upstream `h`-arg rule makes these responses `public, max-age=31536000`. An
# X-Api-Key client carries no cookie and no Authorization, so only the URI tier
# can keep them out. Each case variant has its own root location (nginx
# locations are case-sensitive); the last pair runs under a /sonarr/ mount
# prefix and proves the prefix rebase is case-folded as well.
# Red without ngx_http_cache_turbo_servarr_uri_skip(): every second fetch HITs.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
X-Api-Key: fixture
--- request eval
["GET /API/v3/series?h=x", "GET /API/v3/series?h=x",
 "GET /Initialize.json?h=x", "GET /Initialize.json?h=x",
 "GET /Feed/v3/calendar/Sonarr.ics?h=x", "GET /Feed/v3/calendar/Sonarr.ics?h=x",
 "GET /mediacover/1/poster.jpg", "GET /mediacover/1/poster.jpg",
 "GET /SONARR/Initialize.json?h=x", "GET /SONARR/Initialize.json?h=x"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200,
 200, 200,
 200, 200,
 200, 200,
 200, 200]


=== TEST 16: case folding keeps the segment boundary; public assets still HIT
# Positive control for TEST 15: /APIX is a different segment, and the hashed
# static tree under a case-folded mount stays cacheable.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /APIX?h=1", "GET /APIX?h=1",
 "GET /SONARR/content/app.js?h=abc", "GET /SONARR/content/app.js?h=abc"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200,
 200, 200]


=== TEST 17: other presets stay byte-exact -- /WP-ADMIN/ under wordpress HITs
# Case folding is servarr-only. WordPress's "/wp-admin/" row does not fire on
# "/WP-ADMIN/" (PHP routes byte-exact), so the response caches.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /WP-ADMIN/x", "GET /WP-ADMIN/x"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
