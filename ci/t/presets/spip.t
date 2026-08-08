# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# SPIP preset (docs/spip.md). Ported from test_runtime.py.
#
# Verbatim from the ct_spip_preds[]/ct_spip_uris[]/ct_spip_args[] header
# comment in src, because it names the shape of every test below:
#
#   SPIP prefixes all of its spip_* cookies with an operator-selected cookie
#   prefix. Suffix predicates preserve the meaningful half of each name and
#   fail toward a bypass if another cookie happens to collide. Language and
#   Ajax-mode cookies are presentation state; bypassing them avoids serving
#   the wrong variant without allowing arbitrary client values into the
#   cache key. `?action=` dispatches action handlers and `?var_mode=` forces
#   preview/debug/recalculation modes, neither of which is a shared page
#   render.
#
# ct_spip_cookies[] IS EMPTY -- ALL GUARDING IS VIA PREDICATES
# ------------------------------------------------------------------------
# Unlike most presets in this suite, spip carries no plain-substring cookie
# list at all; every cookie leg runs through ct_spip_preds[], a SUFFIX match
# (not substring-anywhere, and not exact-name) gated by the NONEMPTY value
# predicate. This is the whole point of the preset: SPIP prefixes every
# symbolic cookie name with an operator-selected prefix
# (`<prefix>_session`, `<prefix>_admin`, ...), so an exact-name match would
# never fire on a real install, and presence-only would bypass on a probe
# cookie carrying an empty value. TESTS 3-7 cover the five predicate rows
# independently; TEST 8 is the NONEMPTY negative (an empty value must NOT
# bypass); TEST 9 pins the suffix match firing under an operator prefix.
#
# _lang vs _lang_ecrire: `_lang_ecrire` does not end in `_lang` as a
# substring-from-the-end (the suffix "ecrire" follows it), so the two rows
# are independently reachable and neither subsumes the other. TEST 5/6 pin
# both separately.
#
# THE URI LIST: /ecrire IS SEGMENT-TERMINATED
# ------------------------------------------------------------------------
# ct_spip_uris[] is a single row, "/ecrire" -- SPIP's back-office directory.
# Like every URI row in this engine, the match is prefix-anchored but
# segment-terminated: the byte after the needle must be '/', '.', or
# end-of-URI. TEST 2 is the segment-termination negative: "/ecrireXX"
# continues with 'X', neither a boundary byte nor EOF, and must CACHE.
#
# THE ARG LIST
# ------------------------------------------------------------------------
# ct_spip_args[] is { "action", "var_mode", NULL }. `?action=` dispatches
# SPIP's action handlers (login, logout, form submission); `?var_mode=`
# forces preview/debug/recalculation rendering. TEST 3/4 (arg rows) plus a
# negative proving an unrelated query arg still caches.
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

# Root-anchored /ecrire for the URI row, /spip/ for the path-independent
# cookie/arg/predicate cases. /gen/ is the isolation control -- a DIFFERENT
# preset.
our $Config = ct_config(
    { path => '/ecrire',  backend => 'spip' },
    { path => '/spip/',   backend => 'spip' },
    { path => '/gen/',    backend => 'wordpress' },
);

run_tests();

__DATA__

=== TEST 1: the /ecrire URI row bypasses at the root, with no cookie
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /ecrire", "GET /ecrire"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 2: SEGMENT BOUNDARY -- /ecrireXX must CACHE
# "/ecrire" has no trailing slash in the row, so the boundary branch of
# ngx_http_cache_turbo_uri_prefix() is LIVE. The byte after the needle here
# is 'X', not '/' or '.' and not end-of-URI, so this is a different path
# segment that merely shares the prefix and must cache.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /ecrireXX", "GET /ecrireXX"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 3: the action= arg bypasses
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /spip/page-action?action=login", "GET /spip/page-action?action=login"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 4: the var_mode= arg bypasses
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /spip/page-varmode?var_mode=preview", "GET /spip/page-varmode?var_mode=preview"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 5: an unrelated arg does NOT bypass
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /spip/page-unrelated?page=2", "GET /spip/page-unrelated?page=2"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 6: each of the five predicate rows bypasses independently, NONEMPTY
# _session, _admin, _lang, _lang_ecrire, _accepte_ajax -- each on its own
# path so a shared key cannot mask a missing row. _lang_ecrire is fetched
# separately from _lang to prove neither subsumes the other (it does not
# end in the literal suffix "_lang").
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers eval
["Cookie: spip_session=abc123",
 "Cookie: spip_session=abc123",
 "Cookie: spip_admin=1",
 "Cookie: spip_admin=1",
 "Cookie: spip_lang=en",
 "Cookie: spip_lang=en",
 "Cookie: spip_lang_ecrire=fr",
 "Cookie: spip_lang_ecrire=fr",
 "Cookie: spip_accepte_ajax=1",
 "Cookie: spip_accepte_ajax=1"]
--- request eval
["GET /spip/pred-session", "GET /spip/pred-session",
 "GET /spip/pred-admin",   "GET /spip/pred-admin",
 "GET /spip/pred-lang",    "GET /spip/pred-lang",
 "GET /spip/pred-lang-ecrire", "GET /spip/pred-lang-ecrire",
 "GET /spip/pred-ajax",    "GET /spip/pred-ajax"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: },
 qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200, 200, 200, 200, 200, 200, 200, 200, 200]



=== TEST 7: the NONEMPTY negative -- an EMPTY _session value does NOT bypass
# THE DISTINGUISHING TEST FOR THIS PRESET'S VALUE PREDICATE. The rule is
# NONEMPTY, not presence-only, so a cookie with no value must not bypass.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: spip_session=
--- request eval
["GET /spip/pred-session-empty", "GET /spip/pred-session-empty"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 8: the suffix fires under an operator-selected cookie prefix
# SPIP prefixes every symbolic cookie name with an install-chosen prefix
# (spip_session, myprefix_session, ...). The predicate is a SUFFIX match,
# not exact-name, so a differently-prefixed wire name must still bypass.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: myprefix_session=abc123
--- request eval
["GET /spip/pred-prefix", "GET /spip/pred-prefix"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 9: a bare valueless _admin cookie (no '=') still bypasses -- unparseable fails closed
# Same shape as punbb.t TEST 9 / smf.t TEST 10: a bare cookie with no '='
# carries no readable value, so the predicate engine cannot apply NONEMPTY
# to it and fails closed to bypass rather than guessing it is empty.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: spip_admin
--- request eval
["GET /spip/pred-admin-bare", "GET /spip/pred-admin-bare"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 10: scan does not terminate early -- a non-matching cookie first, then a match
# A leading cookie that does not match any predicate suffix (and, separately,
# a leading cookie with an empty value on a DIFFERENT predicate name) must
# not stop the scan before the real match is reached.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: PHPSESSID=zzz; spip_lang=; spip_admin=1
--- request eval
["GET /spip/pred-scan-twin", "GET /spip/pred-scan-twin"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: }]
--- error_code eval
[200, 200]



=== TEST 11: a cookieless request caches normally
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- request eval
["GET /spip/no-cookie", "GET /spip/no-cookie"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]



=== TEST 12: the spip session cookie under /gen/ (wordpress backend) still HITs
# Isolation control. wordpress has its own cookie/predicate list and the
# spip rows do not leak across backends.
--- http_config eval: $::HttpConfig
--- config eval: $::Config
--- more_headers
Cookie: spip_session=abc123
--- request eval
["GET /gen/topic-iso", "GET /gen/topic-iso"]
--- response_headers eval
[qq{X-Cache: }, qq{X-Cache: HIT}]
--- error_code eval
[200, 200]
