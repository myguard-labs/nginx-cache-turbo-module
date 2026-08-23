# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# P4-2-s3a -- the used-bytes gauge, runtime surface
#
# The ARITHMETIC (exact charge per node+blobref+body, growth across stores,
# exact return to a zero baseline after eviction, the deferred-blob-free leg)
# is covered directly by ci/tests/unit/test_shm_state.c against the sliced
# production bodies -- that is the honest oracle, because from HTTP a byte
# total cannot be predicted (the response the origin actually returns, its
# headers and the CTB4 wire framing all contribute) and an assertion on a
# specific number would be a fixture transcription, not a check.
#
# What the unit harness CANNOT see, and what this file covers, is the runtime
# surface:
#
#   TEST 1: the field is exported by the JSON admin endpoint, is zero on a
#           zone that has stored nothing, and is NONZERO after real traffic
#           has populated the zone. The zero-then-nonzero pair is the point:
#           a hardcoded constant, or a field wired to the wrong shctx member,
#           fails one leg or the other.
#   TEST 2: the Prometheus rendering. admin_stats_prometheus() carries a
#           hand-maintained length budget that has truncated its final
#           metric twice before (see the len= comment in admin.c).
#           Asserting used_bytes's own HELP/TYPE/line block renders in FULL
#           -- name, label and value, terminated by a newline -- catches a
#           stale budget that truncates AT OR BEFORE this block. used_bytes
#           is no longer necessarily the last metric emitted (C3 appended
#           `markers` after it) -- ci/tools/lint-admin-buffer-budget.py is
#           the budget's real, position-independent guard; re-measures the
#           format string's exact byte length rather than sampling one
#           field's line, so it catches a stale budget regardless of which
#           metric ends up last.
use lib 'ci/t/lib';
use CacheTurbo qw( ct_http_config ct_config ct_origin_port );
use Test::Nginx::Socket 'no_plan';

repeat_each(1);
run_tests();

__DATA__

=== TEST 1: used_bytes is exported, zero when empty, nonzero once populated
--- http_config eval: CacheTurbo::ct_http_config()
--- config eval
    CacheTurbo::ct_config(
        { path => '/ub/json', backend => 'wordpress' },
    ) . <<'EOC'
        location = /_cache_ubjson {
            cache_turbo_admin main;
        }
EOC
--- request eval
["GET /_cache_ubjson", "GET /ub/json", "GET /ub/json", "GET /_cache_ubjson"]
--- response_body_like eval
[qr/"used_bytes":0[,}]/,
 qr/./, qr/./,
 qr/"used_bytes":[1-9]\d*[,}]/]
--- error_code eval
[200, 200, 200, 200]



=== TEST 2: the Prometheus rendering of used_bytes is not truncated
--- http_config eval: CacheTurbo::ct_http_config()
--- config eval
    CacheTurbo::ct_config(
        { path => '/ub/prom', backend => 'wordpress' },
    ) . <<'EOC'
        location = /_cache_ubprom {
            cache_turbo_admin main;
        }
EOC
--- request eval
["GET /ub/prom", "GET /_cache_ubprom?format=prometheus"]
--- response_body_like eval
[qr/./,
 qr/# TYPE cache_turbo_used_bytes gauge\ncache_turbo_used_bytes\{zone="main"\} [1-9]\d*\n/s]
--- error_code eval
[200, 200]
