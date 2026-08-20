# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# P4-1b -- W-TinyLFU admission control, runtime surface
#
# The DECISION itself (shm_admit()'s comparison, its three fail-open
# directions and its termination property) is covered directly by
# ci/tests/unit/test_shm_state.c, which is the honest oracle: an end-to-end
# "was it cached?" assertion cannot distinguish an admission refusal from a
# slab failure, an unstorable status or a bypass, and all four leave the same
# absent entry. What CANNOT be seen from the unit harness, and is therefore
# what this file covers, is the runtime surface:
#
#   TEST 1: the SHIPPED DEFAULT. A zone declared with NO admission parameter
#           at all must come up with the policy off and refuse nothing. This
#           is deliberately the compiled-in default with no directive -- a
#           test that wrote `admission=off` explicitly would pass even if the
#           default had flipped, so it could not prove the default at all.
#   TEST 2: `admission=on` parses, the worker starts, and the three new stat
#           fields are exported by the JSON admin endpoint. sketch_bumps > 0
#           after real traffic is what proves the sketch was actually
#           allocated and is being fed -- a zone whose sketch allocation
#           failed reports 0 there forever, and every admission decision is
#           then inert.
#   TEST 3: the Prometheus rendering of the same three metrics. The
#           HELP/TYPE prose and the per-metric length budget in
#           admin_stats_prometheus() grow together; a stale budget truncates
#           the LAST metric emitted (this has bitten twice before, see the
#           len= comment in admin.c), and the three P4-1b lines ARE now the
#           last three. Asserting the final line renders in full is what
#           catches an under-budgeted buffer.
#   TEST 4: a bad admission value is a hard config error, not a silently
#           coerced default. Same rule cache_turbo_scan_resistant follows:
#           a config that is accepted but means something else is worse than
#           one that refuses to start.

use lib 'ci/t/lib';
use CacheTurbo qw( ct_http_config ct_config ct_origin_port );
use Test::Nginx::Socket 'no_plan';

repeat_each(1);
run_tests();

__DATA__

=== TEST 1: the SHIPPED DEFAULT -- no admission parameter, policy off, nothing refused
--- http_config eval: CacheTurbo::ct_http_config()
--- config eval
    CacheTurbo::ct_config(
        { path => '/adm/default', backend => 'wordpress' },
    ) . <<'EOC'
        location = /_cache_admdef {
            cache_turbo_admin main;
        }
EOC
--- request eval
["GET /adm/default", "GET /adm/default", "GET /_cache_admdef"]
--- response_body_like eval
[qr/./, qr/./, qr/"admission_refused":0[,}]/]
--- error_code eval
[200, 200, 200]



=== TEST 2: admission=on parses, starts, and exports the three stat fields
--- http_config eval
    my $op = CacheTurbo::ct_origin_port();
    my $c = CacheTurbo::ct_http_config();
    $c =~ s/cache_turbo_zone main 16m;/cache_turbo_zone main 16m admission=on;/;
    $c
--- config eval
    CacheTurbo::ct_config(
        { path => '/adm/on', backend => 'wordpress' },
    ) . <<'EOC'
        location = /_cache_admon {
            cache_turbo_admin main;
        }
EOC
--- request eval
["GET /adm/on", "GET /adm/on", "GET /_cache_admon"]
--- response_body_like eval
[qr/./, qr/./,
 qr/"sketch_gen":\d+,"sketch_bumps":[1-9]\d*,"admission_refused":\d+\}/]
--- error_code eval
[200, 200, 200]



=== TEST 3: the Prometheus rendering of the three metrics is not truncated
--- http_config eval
    my $c = CacheTurbo::ct_http_config();
    $c =~ s/cache_turbo_zone main 16m;/cache_turbo_zone main 16m admission=on;/;
    $c
--- config eval
    CacheTurbo::ct_config(
        { path => '/adm/prom', backend => 'wordpress' },
    ) . <<'EOC'
        location = /_cache_admprom {
            cache_turbo_admin main;
        }
EOC
--- request eval
["GET /adm/prom", "GET /_cache_admprom?format=prometheus"]
--- response_body_like eval
[qr/./,
 qr/cache_turbo_sketch_bumps_total\{zone="main"\} \d+\n.*cache_turbo_admission_refused_total\{zone="main"\} \d+\n/s]
--- error_code eval
[200, 200]



=== TEST 4: a bad admission value refuses to start rather than coercing a default
--- http_config eval
    my $c = CacheTurbo::ct_http_config();
    $c =~ s/cache_turbo_zone main 16m;/cache_turbo_zone main 16m admission=maybe;/;
    $c
--- config eval
    CacheTurbo::ct_config( { path => '/adm/bad', backend => 'wordpress' } )
--- must_die
--- error_log
cache_turbo_zone: bad admission value "admission=maybe"
