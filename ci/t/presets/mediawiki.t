# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# MediaWiki preset (docs/mediawiki.md). Ported from test_mediawiki_preset() in
# ci/tools/test_runtime.py.
#
# THE PRESET HAS NO URI RULES -- ct_mw_uris[] is NULL, and that is the whole
# point of the file's first test, not an omission here.
# ----------------------------------------------------------------------------
# Three used to be here: /index.php, /load.php, /api.php. All three were wrong.
# On a stock wiki $wgArticlePath is /index.php?title=Foo (or /index.php/Foo) --
# i.e. /index.php IS the article READ path, so bypassing it threw away 100% of
# article reads. /load.php (ResourceLoader) and /api.php are the hottest
# cacheable objects on the site; Wikimedia's production VCL ring-fences them
# against being made private, by ticket number (T102898, T113007):
#   // Only apply to pages. Don't steal cachability of api.php, load.php, etc.
#   // (T102898, T113007)
# TEST 1 is the regression guard for the single worst rule this registry ever
# shipped: it is INVERTED from what the original preset asserted, and pins
# /index.php?title=Foo as CACHEABLE.
#
# COOKIES ARE $wgCookiePrefix-SUFFIXED, MATCHED AS A RAW SUBSTRING
# ----------------------------------------------------------------------------
# $wgCookiePrefix defaults to the DATABASE NAME, so there is no shippable
# literal prefix -- same shape as joomla's md5 session cookie, opposite fix:
# here the SUFFIX is fixed. ct_mw_cookies[] is evaluated by
# ngx_http_cache_turbo_cookie_has(), a raw ngx_strnstr() search for the needle
# ANYWHERE in the whole Cookie header value -- it is not a name/value-pair
# parser and does not anchor on the suffix actually being at the END of a
# cookie NAME. Do not "fix" this into a name-anchored match.
#
# MATCH WHAT UPSTREAM MATCHES -- Token= and _session= are shipped because
# MediaWiki's own getVaryCookies() says plainly: "Vary on token and session
# because those are the real authn determiners. UserID and UserName don't
# matter without those." UserID= is kept too, as cheap belt-and-braces (it is
# cleared for an anonymous user, so it costs nothing to carry).
#
# UserName= IS DELIBERATELY NOT MATCHED, and TEST 4 pins the omission as a
# decision, not an oversight: unpersistSession() does NOT clear it on logout
# (it pre-fills the login form), so EVERY visitor who has ever logged in keeps
# sending it forever, long after they are an ordinary anonymous reader.
# Bypassing on it is a permanent hit-rate loss with zero safety gain.
#
# NO PREDICATES, NO KEY COOKIES
# ----------------------------------------------------------------------------
# The mediawiki row in ngx_http_cache_turbo_presets[] carries NULL for both
# cookie_preds and key_cookies -- only the cookie and arg legs below apply;
# there is no value-predicate leg and no key-cookie leg to test here.
#
# THE ARG LEG IS THE DYNAMIC SURFACE -- QUERY ARGS, NOT PATHS
# ----------------------------------------------------------------------------
# /wiki/<Title> is the cacheable read path; the mutating surface is entirely in
# ?action=. ct_mw_args[] lists ONLY the MUTATING half of
# ActionFactory::CORE_ACTIONS (edit/submit/delete/protect/unprotect/purge/
# rollback/revert/watch/unwatch/markpatrolled/mcrundo/mcrrestore), plus
# veaction (VisualEditor, always dynamic) and returnto (both bare-NAME
# presence rules). action=view/history/raw/render/info/credits, diff= and
# oldid= are all deliberately ABSENT -- they are deterministic, shared, hot,
# and a blanket "presence of action= bypasses" rule was rejected because it
# would bypass those too. TEST 6 pins every one of them as still cacheable so a
# future editor reaching for the reflex "just bypass all action=" cannot do it
# silently.
#
# These arg rows are cookie-less bypasses that do not rely on MediaWiki's own
# Cache-Control floor (OutputPage::$mCdnMaxage starts at 0 and is raised only
# for a ViewAction or a purgeable canonical URL -- see the source comment on
# ct_mw_args in src/ngx_http_cache_turbo_module.c). The origin fixture here
# sends no Cache-Control at all, which is precisely the
# `cache_turbo_cache_control ignore` shape the rows exist to cover.
#
# See ci/t/presets/xenforo.t for why every bypass case is fetched TWICE and why
# these are `--- request eval` arrays rather than `--- pipelined_requests`.
# See ci/t/presets/mybb.t for the exact-vs-suffix key/predicate asymmetry
# pinned elsewhere in this registry (not exercised by this preset -- mediawiki
# has no predicate or key-cookie leg at all).

use lib 'ci/t/lib';
use Test::Nginx::Socket 'no_plan';
use CacheTurbo qw( ct_http_config ct_config );

repeat_each(1);
no_long_string();

our $HttpConfig = ct_http_config();

# The preset has no URI rules, so every location below is opt-in purely
# through cache_turbo_backend mediawiki -- there is no prefix rule to anchor a
# location at root for. /index.php carries TEST 1 (the article-read regression
# guard); /wiki/ carries the cookie and arg cases. /gen/ is the isolation
# control -- a DIFFERENT preset, proving the mediawiki cookie/arg rows are
# opt-in and do not leak into another backend's location.
our $Config = ct_config(
    { path => '/index.php', backend => 'mediawiki' },
    { path => '/wiki/',     backend => 'mediawiki' },
    { path => '/gen/',      backend => 'wordpress'  },
);

run_tests();

__DATA__

=== TEST 1: /index.php?title=Foo is the article READ path and must CACHE
# On a stock wiki $wgArticlePath is /index.php?title=Foo -- this IS the
# article read path, not a dynamic one. This is the regression guard for the
# worst rule the registry ever shipped (a blanket /index.php bypass rule that
# threw away 100% of article reads on any wiki without short-URL rewrites).
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /index.php?title=Foo", "GET /index.php?title=Foo"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 2: ?veaction= (VisualEditor) always bypasses -- bare-NAME presence rule
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wiki/Article-ve?veaction=edit", "GET /wiki/Article-ve?veaction=edit"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 3: the identity cookies bypass, whatever prefix the site happens to use
# Token= / _session= / UserID= are matched as a raw substring ANYWHERE in the
# Cookie header value, so they bypass regardless of the per-install
# $wgCookiePrefix ("mywiki" here is arbitrary). Token and _session are what
# upstream's own getVaryCookies() calls the real authn determiners; UserID is
# cheap belt-and-braces carried alongside them -- THE LEAK GUARD.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers eval
["Cookie: mywikiToken=deadbeef", "Cookie: mywikiToken=deadbeef",
 "Cookie: mywiki_session=abc123", "Cookie: mywiki_session=abc123",
 "Cookie: mywikiUserID=42", "Cookie: mywikiUserID=42"]
--- request eval
["GET /wiki/Article-a", "GET /wiki/Article-a",
 "GET /wiki/Article-a", "GET /wiki/Article-a",
 "GET /wiki/Article-a", "GET /wiki/Article-a"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200]



=== TEST 4: UserName= does NOT bypass -- deliberately omitted, not an oversight
# unpersistSession() does not clear UserName on logout (it pre-fills the login
# form), so every visitor who has ever logged in keeps sending it forever, long
# after they are an ordinary anonymous reader. Bypassing on it would be a
# permanent hit-rate loss for zero safety gain -- an ex-member reading
# anonymously must still cache.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: mywikiUserName=Bob
--- request eval
["GET /wiki/Article-b", "GET /wiki/Article-b"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 5: every mutating core action bypasses, cookie-less
# Every action in ActionFactory::CORE_ACTIONS' mutating half must bypass on
# the arg alone, with no cookie present -- a logged-in actor is already
# covered by TEST 3, and this leg exercises the cookie-less
# `cache_turbo_cache_control ignore` shape the rows exist to cover (the origin
# fixture here sends no Cache-Control at all).
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wiki/Article-edit?action=edit", "GET /wiki/Article-edit?action=edit",
 "GET /wiki/Article-submit?action=submit", "GET /wiki/Article-submit?action=submit",
 "GET /wiki/Article-delete?action=delete", "GET /wiki/Article-delete?action=delete",
 "GET /wiki/Article-protect?action=protect", "GET /wiki/Article-protect?action=protect",
 "GET /wiki/Article-unprotect?action=unprotect", "GET /wiki/Article-unprotect?action=unprotect",
 "GET /wiki/Article-purge?action=purge", "GET /wiki/Article-purge?action=purge",
 "GET /wiki/Article-rollback?action=rollback", "GET /wiki/Article-rollback?action=rollback",
 "GET /wiki/Article-revert?action=revert", "GET /wiki/Article-revert?action=revert",
 "GET /wiki/Article-watch?action=watch", "GET /wiki/Article-watch?action=watch",
 "GET /wiki/Article-unwatch?action=unwatch", "GET /wiki/Article-unwatch?action=unwatch",
 "GET /wiki/Article-markpatrolled?action=markpatrolled", "GET /wiki/Article-markpatrolled?action=markpatrolled",
 "GET /wiki/Article-mcrundo?action=mcrundo", "GET /wiki/Article-mcrundo?action=mcrundo",
 "GET /wiki/Article-mcrrestore?action=mcrrestore", "GET /wiki/Article-mcrrestore?action=mcrrestore"]
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
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200,
 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200]



=== TEST 6: action is not the first argument, and may be percent-encoded
# MediaWiki writes ?title=Foo&action=edit -- the mutating arg is not the first
# argument in the query string, and the arg scanner must keep scanning past a
# non-match. PHP also routes a percent-encoded name identically
# (?%61ction=delete resolves to action=delete), so the scanner must decode
# before comparing.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /index.php?title=Foo&action=edit", "GET /index.php?title=Foo&action=edit",
 "GET /index.php?title=Foo&%61ction=delete", "GET /index.php?title=Foo&%61ction=delete"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200]



=== TEST 7: the deliberately-cacheable actions all stay cacheable -- THE NEGATIVE HALF
# action=view/history/raw/render/info/credits, diff= and oldid= are all
# deliberately ABSENT from ct_mw_args -- they are deterministic, shared, hot,
# and a blanket "presence of action= bypasses" rule was rejected because it
# would have caught these too. render/info/credits/view are the rows a future
# editor is most likely to add by reflex when extending the mutating list --
# they are core actions sitting right beside the ones above in CORE_ACTIONS,
# and pinning them here is what makes the list a decision rather than an
# accident.
# Each case uses a DISTINCT path -- cache_turbo_key is $uri (path only, no
# query string, see ct_location() in ci/t/lib/CacheTurbo.pm), so reusing one
# path across sub-cases would warm the key on the first sub-case and every
# later "first fetch" would already be a HIT regardless of whether the arg
# actually stays cacheable.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wiki/Article-c1", "GET /wiki/Article-c1",
 "GET /wiki/Article-c2?action=raw", "GET /wiki/Article-c2?action=raw",
 "GET /wiki/Article-c3?action=history", "GET /wiki/Article-c3?action=history",
 "GET /wiki/Article-c4?action=render", "GET /wiki/Article-c4?action=render",
 "GET /wiki/Article-c5?action=info", "GET /wiki/Article-c5?action=info",
 "GET /wiki/Article-c6?action=credits", "GET /wiki/Article-c6?action=credits",
 "GET /wiki/Article-c7?action=view", "GET /wiki/Article-c7?action=view",
 "GET /wiki/Article-c8?oldid=12345", "GET /wiki/Article-c8?oldid=12345",
 "GET /wiki/Article-c9?diff=12345", "GET /wiki/Article-c9?diff=12345"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT},
 qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200,
 200, 200, 200]



=== TEST 8: a cookieless anonymous reader still caches
# The preset is not a blanket bypass -- that is the whole point of it existing
# rather than just disabling the cache for the location.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /wiki/Article-d", "GET /wiki/Article-d"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 9: the mediawiki rows do not leak into another backend's location
# /gen/ runs the wordpress preset. ?action=edit is a mediawiki arg rule, not a
# wordpress one, so the generic location must cache it -- proving the rule is
# preset-scoped, not global.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /gen/wiki?action=edit", "GET /gen/wiki?action=edit"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 10: a mediawiki Token cookie does not bypass under the wordpress preset
# The cookie half of TEST 9. mywikiToken=... is not a wordpress signal, so the
# generic location must cache it -- proving the cookie rule is preset-scoped.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: mywikiToken=deadbeef
--- request eval
["GET /gen/article", "GET /gen/article"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
