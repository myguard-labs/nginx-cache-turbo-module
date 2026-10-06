# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Next.js preset (docs/react.md). The first preset with a REQUEST-HEADER tier.
#
# WHY THIS PRESET NEEDS ITS OWN ORIGIN
# ------------------------------------------------------------------------
# The App Router serves the HTML document and the React Server Component
# payload (text/x-component) of a page at the SAME URL, selected by the `RSC: 1`
# request header, and marks every App Router response
#
#   Vary: rsc, next-router-state-tree, next-router-prefetch,
#         next-router-segment-prefetch
#
# Default auto-Vary refuses an unknown Vary axis, so without the preset an App
# Router page is never cached. With `cache_turbo_vary_ignore` on those names and
# no bypass, one `RSC: 1` request poisons the HTML entry for every visitor
# (GHSA-wfc6-r584-vfw7). The preset bypasses every request carrying a router
# header and treats a Vary axis naming one of them as SATISFIED (the header is
# identically absent for every stored and served representation), see
# ngx_http_cache_turbo_vary_preset_satisfied() in src/ngx_http_cache_turbo_vary.c.
#
# The shared ct_http_config() origin sends no Vary at all, so it cannot
# exercise any of that. A dedicated origin on ct_origin_port() + 4 (the same
# slot magento.t and shopware6.t use; each .t owns its own nginx) sends the
# exact Next.js Vary and ECHOES $http_rsc into the body, so "the RSC client got
# the HTML entry" and "the HTML entry holds the RSC payload" are both visible by
# content: `rsc=1` marks a body produced for an RSC request, `rsc=;` one
# produced for a document navigation.
#
# Origin paths:
#   /xv/          Next.js Vary PLUS an axis the preset does not own (x-foo):
#                 must stay uncacheable -- the preset satisfies only its own
#                 header names, never the whole Vary line.
#   /wp/novary/   no Vary: positive control proving the wordpress location
#                 below CAN cache, so its never-HIT under the Next.js Vary is
#                 the Vary refusal and not some other veto.
#   /             everything else: Next.js Vary.
#
# NEGATIVE CONTROLS (mutations, observed red, not in-file):
#   - ngx_http_cache_turbo_vary_preset_satisfied() compiled out (`return 0;`
#     first): every HIT arm under a nextjs location (TEST 1-9) goes red -- the
#     nextjs location never HITs, exactly like the wordpress location in
#     TEST 11.
#   - the auto_header_present() call in auto_skip compiled out (`0 &&`): the
#     RSC request is served the HTML entry (TEST 2) and every header row HITs
#     (TEST 4). TEST 3 stays green because the capture re-check still refuses
#     the RSC store -- the two halves are independent.
#   - the capture re-check made unconditional (`return 1;`): TEST 13 goes red,
#     the RSC payload is stored as the bypass_stale fallback copy.
#
# See ci/t/presets/discourse.t for why every bypass case is fetched TWICE (a
# bypass and a first-time MISS both lack X-Cache) and why these are
# `--- request eval` arrays rather than `--- pipelined_requests`.

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_origin_port );

repeat_each(1);
no_long_string();

our $NxOriginPort = ct_origin_port() + 4;
our $NxVary = 'rsc, next-router-state-tree, next-router-prefetch, '
    . 'next-router-segment-prefetch';

# `nxbs` is a zone of its own so TEST 13 can read used_bytes / the Vary refusal
# counter without the other blocks' entries in it.
our $HttpConfig = ct_http_config() . <<"EOC";
    cache_turbo_zone nxbs 8m;

    server {
        listen       127.0.0.1:$NxOriginPort;
        server_name  nextjs-origin;

        location / {
            add_header Cache-Control "public, max-age=30" always;
            add_header Vary "$NxVary" always;
            return 200 "origin:\$request_uri:\$connection:\$connection_requests:\$msec:rsc=\$http_rsc;ck=\$http_cookie\\n";
        }

        location /xv/ {
            add_header Cache-Control "public, max-age=30" always;
            add_header Vary "$NxVary, x-foo" always;
            return 200 "origin:\$request_uri:\$connection:\$connection_requests:\$msec:rsc=\$http_rsc;\\n";
        }

        location /wp/novary/ {
            add_header Cache-Control "public, max-age=30" always;
            return 200 "origin:\$request_uri:\$connection:\$connection_requests:\$msec:rsc=\$http_rsc;\\n";
        }
    }
EOC

# One location builder for this file: every location proxies to the Next.js
# origin with the URI unchanged (no trailing slash on proxy_pass), so the origin
# path selection above sees exactly what the client asked for.
sub nx_location {
    my ($path, $backend) = @_;
    my $b = defined $backend ? "cache_turbo_backend $backend;" : '';
    return <<"EOL";
        location $path {
            cache_turbo         main;
            $b
            cache_turbo_key     \$uri;
            cache_turbo_valid   30s;
            proxy_pass http://127.0.0.1:$NxOriginPort;
        }
EOL
}

# Test::Nginx already owns `location /`, so the preset sits on prefixed
# locations: /n/ for the page arms, /api for the `/api/` URI row (a byte-0
# prefix, so it needs its own location anchored there; `/api` without the slash
# also catches /apidocs, the near-miss control), /xv/ for the foreign-axis
# case. /wp/ (a different preset) and /nobk/ (no preset at all) are the
# isolation controls for the default auto-Vary refusal.
our $Config = nx_location('/n/', 'nextjs')
    . nx_location('/api', 'nextjs')
    . nx_location('/xv/', 'nextjs')
    . nx_location('/wp/', 'wordpress')
    . nx_location('/nobk/', undef) . <<"EOL";
        location /bs/ {
            cache_turbo         nxbs;
            cache_turbo_backend nextjs;
            cache_turbo_key     \$uri;
            cache_turbo_valid   30s;
            cache_turbo_bypass_stale_uri /bs/;
            proxy_pass http://127.0.0.1:$NxOriginPort;
        }
        location = /_nxbs {
            cache_turbo_admin nxbs;
        }
EOL

run_tests();

__DATA__

=== TEST 1: plain document GET is cached (Vary satisfied), MISS then HIT
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /n/blog/post-1", "GET /n/blog/post-1"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- response_body_like eval
[qr{^origin:/n/blog/post-1:.*:rsc=;}, qr{^origin:/n/blog/post-1:.*:rsc=;}]
--- error_code eval
[200, 200]



=== TEST 2: RSC: 1 never receives the cached HTML entry and never replaces it
# Prime the HTML entry, then two RSC requests on the SAME key: both must reach
# the origin (body says rsc=1, not the primed rsc=;), and the document entry
# must still be the HTML one afterwards (HIT, body rsc=;).
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /n/page/a", "GET /n/page/a", "GET /n/page/a", "GET /n/page/a"]
--- more_headers eval
["", "RSC: 1", "RSC: 1", ""]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: HIT}]
--- response_body_like eval
[qr{:rsc=;}, qr{:rsc=1;}, qr{:rsc=1;}, qr{:rsc=;}]
--- error_code eval
[200, 200, 200, 200]



=== TEST 3: RSC: 1 on a COLD key does not store the payload (no poisoning)
# The payload responses carry the same cacheable headers as the HTML; if either
# RSC request were captured, request 3 would be a HIT serving rsc=1.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /n/page/cold", "GET /n/page/cold", "GET /n/page/cold", "GET /n/page/cold"]
--- more_headers eval
["RSC: 1", "RSC: 1", "", ""]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: HIT}]
--- response_body_like eval
[qr{:rsc=1;}, qr{:rsc=1;}, qr{:rsc=;}, qr{:rsc=;}]
--- error_code eval
[200, 200, 200, 200]



=== TEST 4: every request-header row bypasses a WARM entry
# Request 1 primes /hdr/x and request 2 proves it HITs; every following request
# carries exactly one router/internal header and must not be served that entry.
# Header names are matched case-insensitively and on presence alone: the
# lowercase `rsc` and the EMPTY `RSC:` arms pin both.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /n/hdr/x", "GET /n/hdr/x",
 "GET /n/hdr/x", "GET /n/hdr/x", "GET /n/hdr/x", "GET /n/hdr/x", "GET /n/hdr/x",
 "GET /n/hdr/x", "GET /n/hdr/x", "GET /n/hdr/x", "GET /n/hdr/x", "GET /n/hdr/x",
 "GET /n/hdr/x", "GET /n/hdr/x",
 "GET /n/hdr/x"]
--- more_headers eval
["", "",
 "RSC: 1",
 "Next-Router-State-Tree: %5B%22%22%5D",
 "Next-Router-Prefetch: 1",
 "Next-Router-Segment-Prefetch: /_tree",
 "Next-Url: /intercepted",
 "Next-Action: 7f3a",
 "X-Middleware-Prefetch: 1",
 "X-Nextjs-Data: 1",
 "X-Now-Route-Matches: 1",
 "X-Middleware-Subrequest: middleware",
 "rsc: 1",
 "RSC:",
 ""]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200]



=== TEST 5: the _rsc cache-busting arg bypasses even without the RSC header
# The key is $uri, so without the arg row ?_rsc=... would HIT the warm entry.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /n/rscarg", "GET /n/rscarg", "GET /n/rscarg?_rsc=1x2y3", "GET /n/rscarg?_rsc=1x2y3",
 "GET /n/rscarg?_rsc", "GET /n/rscarg?_rsc"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}, qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 6: an unrelated arg does not bypass
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /n/plainarg?page=2", "GET /n/plainarg?page=2"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 7: every session / draft-mode cookie row bypasses a WARM entry
# Covers each ct_nextjs_cookies[] row plus the __Secure- prefix and .0 chunk
# forms the substring rows are documented to catch.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /n/ck/x", "GET /n/ck/x",
 "GET /n/ck/x", "GET /n/ck/x", "GET /n/ck/x", "GET /n/ck/x", "GET /n/ck/x",
 "GET /n/ck/x", "GET /n/ck/x", "GET /n/ck/x", "GET /n/ck/x", "GET /n/ck/x",
 "GET /n/ck/x"]
--- more_headers eval
["", "",
 "Cookie: __prerender_bypass=abc",
 "Cookie: __next_preview_data=abc",
 "Cookie: next-auth.session-token=abc",
 "Cookie: __Secure-next-auth.session-token=abc",
 "Cookie: authjs.session-token.0=abc",
 "Cookie: __Secure-authjs.session-token=abc",
 "Cookie: __session=eyJabc",
 "Cookie: better-auth.session_token=abc",
 "Cookie: sb-abcdefgh-auth-token=base64-abc",
 "Cookie: theme=dark; next-auth.session-token=abc",
 ""]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200]



=== TEST 8: guest-issued auth cookies do NOT bypass
# Clerk sets __client_uat=0 for signed-out visitors; Auth.js issues csrf-token
# and callback-url cookies before login. None of them is a session.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /n/guest/a", "GET /n/guest/a", "GET /n/guest/a", "GET /n/guest/a"]
--- more_headers eval
["Cookie: __client_uat=0",
 "Cookie: __client_uat=0",
 "Cookie: next-auth.csrf-token=abc; authjs.callback-url=%2F",
 "Cookie: __Host-next-auth.csrf-token=abc"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}, qq{X-Cache: HIT}, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]



=== TEST 9: /api/ bypasses; a sibling path that only starts with "api" does not
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /api/user", "GET /api/user", "GET /apidocs", "GET /apidocs"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200]



=== TEST 10: a Vary axis the preset does not own still refuses the store
# rsc..segment-prefetch are satisfied, x-foo is not: the response stays
# uncacheable under the nextjs preset.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /xv/page", "GET /xv/page", "GET /xv/page"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200]



=== TEST 11: isolation -- wordpress and no-preset locations keep refusing the Next.js Vary
# Same origin, same Vary, no nextjs preset: the default auto-Vary refusal of
# unknown axes is untouched. /wp/novary/ is the positive control that the
# wordpress location caches when the Vary is absent.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wp/page", "GET /wp/page", "GET /wp/page",
 "GET /nobk/page", "GET /nobk/page", "GET /nobk/page",
 "GET /wp/novary/page", "GET /wp/novary/page"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200]



=== TEST 12: RSC header does not bypass a location without the preset
# The header tier is opt-in like every other tier: under wordpress an RSC
# request on a Vary-free URL is an ordinary request and HITs the warm entry.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wp/novary/rsc", "GET /wp/novary/rsc", "GET /wp/novary/rsc"]
--- more_headers eval
["", "", "RSC: 1"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200]



=== TEST 13: a capture ahead of auto_skip (bypass_stale) still refuses an RSC response
# cache_turbo_bypass_stale_uri declines BEFORE auto_skip and still captures (the
# breaker-only store), so the header tier never sees these requests. The Vary
# classifier re-checks the captured request itself: with `RSC: 1` present the
# rsc axis is NOT satisfied and the store is refused as an unsafe Vary
# (used_bytes stays 0, refuse_vary_unsafe 1). The plain request on the same
# URL is the positive control: it is stored (used_bytes > 0). Without the
# re-check the RSC payload would be stored here as the breaker fallback copy.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /_nxbs", "GET /bs/page", "GET /_nxbs", "GET /bs/page", "GET /_nxbs"]
--- more_headers eval
["", "RSC: 1", "", "", ""]
--- response_body_like eval
[qr/"refuse_vary_unsafe":0,.*"used_bytes":0[,}]/,
 qr/:rsc=1;/,
 qr/"refuse_vary_unsafe":1,.*"used_bytes":0[,}]/,
 qr/:rsc=;/,
 qr/"refuse_vary_unsafe":1,.*"used_bytes":[1-9]\d*[,}]/]
--- error_code eval
[200, 200, 200, 200, 200]
