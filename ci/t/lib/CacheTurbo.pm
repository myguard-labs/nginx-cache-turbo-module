# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Shared scaffolding for the ci/t/presets/*.t suite.
#
# Every preset file needs the same three things: a cache zone, an origin that
# returns a UNIQUE BODY per request, and a `cache_turbo_backend <preset>`
# location to drive traffic at. This module supplies all three so a preset file
# contains only its own rules and its own provenance.
#
# WHY THE ORIGIN MUST VARY ITS BODY
# ---------------------------------
# Several preset assertions are of the form "a different key-cookie value must
# not be served the FIRST value's cached body". That is only detectable if two
# origin responses differ. A static `return 200 "ok"` origin makes those
# assertions vacuous -- they would pass with key folding removed entirely.
# ct_http_config() therefore stamps a unique value into every origin response.
#
# WHY ONE --- config PER FILE
# ---------------------------
# Test::Nginx::Socket restarts nginx whenever a block's `--- config` differs
# from the previous block's (Test/Nginx/Util.pm, $should_restart). Blocks that
# share one byte-identical config reuse the running server. Preset files
# therefore declare the config ONCE via ct_config() and every block reuses it,
# which is why a 20-block preset file costs ONE nginx spawn rather than 20.
#
# Cross-file reuse is NOT possible: prove runs each .t in its own perl process
# and $PrevConfig is a package global, so the floor is one spawn per file.

package CacheTurbo;

use strict;
use warnings;

use File::Spec ();
use IO::Socket::INET;

use Test::Nginx::Util qw( server_port );

use Exporter 'import';
our @EXPORT_OK = qw( ct_http_config ct_location ct_config ct_origin_port );

# THE PORT THE SCAFFOLD PROVED FREE IS NOT THE PORT NGINX BINDS
# -------------------------------------------------------------
# gen_rand_port() (Util.pm) probes a candidate with LocalAddr => $ServerAddr,
# i.e. 127.0.0.1 ONLY. The server it then generates listens on a BARE port --
# Util.pm's template is `listen $ServerPort$listen_opts;` with no address -- so
# nginx binds 0.0.0.0, every interface. A wildcard bind needs the port free
# everywhere, so a loopback-scoped probe systematically over-approximates
# availability: anything on this host holding the port on a non-loopback
# address passes the probe and then fails the bind.
#
# On a shared CI runner that is not hypothetical. Observed 2026-08-17 (run
# 32075040354): every preset assertion PASSED (278 tests, "All tests
# successful") and the job still failed 255, because nginx could not bind
# 0.0.0.0:34782 -- a port the scaffold had just proved free on 127.0.0.1.
#
# It does not look like a race and does not behave like one. Test::Nginx
# retries the SAME port ~20 times over 20s and then bails the whole file set;
# it never re-draws. So a stable off-loopback holder is a stable failure, which
# is why this reproduces only on a loaded runner and never on an idle box, and
# why green reruns say nothing about it.
#
# Both halves are fixed here rather than upstream: probe the address nginx
# actually binds, and RE-DRAW instead of retrying a doomed port. This runs at
# import time -- every .t does `use Test::Nginx::Socket` (which runs Util.pm's
# $Randomize block and sets $ServerPort) before `use CacheTurbo`, so the port
# is already chosen and no nginx has started yet.
#
# The fence step in ci.yml and the "proved free" note in
# ci/tools/lint-ci-ports.sh rest on the same loopback-only premise; both are
# annotated to point here.

# A port is usable only if BOTH the nginx listener (wildcard) and the origin
# beside it (loopback, +1) can bind. Probing wildcard alone would still leave
# the origin's port unchecked -- the old code never probed +1 at all, on the
# false premise that Util.pm "reserves" $ServerPort+1..+3. It does not: that
# comment in gen_rand_port only explains why the random RANGE starts at 1988.
# Nothing binds, tracks or excludes +1.
sub _pair_is_free {
    my ($port) = @_;

    return 0 if $port + 1 > 65535;

    # Same scope nginx uses. No SO_REUSEADDR: a successful bind here must mean
    # the port is genuinely unheld, not that we were allowed to share it.
    my $wildcard = IO::Socket::INET->new(
        LocalAddr => '0.0.0.0',
        LocalPort => $port,
        Proto     => 'tcp',
        Listen    => 5,
    ) or return 0;

    my $origin = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1',
        LocalPort => $port + 1,
        Proto     => 'tcp',
        Listen    => 5,
    );

    # Close in the same order they were opened; the caller re-binds immediately.
    $wildcard->close();
    return 0 unless defined $origin;
    $origin->close();

    return 1;
}

# Util.pm derives the servroot and its log paths from $ServerPort ONCE, at its
# own import (Util.pm:601 `t/servroot_$ServerPort`, then $LogDir/$ErrLogFile/
# $AccLogFile under it) -- which is before this module loads. Changing the port
# without repointing them would leave this process writing into another job's
# servroot_<port>, reintroducing under a new name exactly the cross-job sharing
# the randomization exists to prevent. It would also defeat Util.pm's cleanup
# guard, which only removes a dir matching m{/t/servroot_\d+}.
sub _repoint_servroot {
    my ($port) = @_;

    my $root     = File::Spec->rel2abs("t/servroot_$port");
    my $log_dir  = File::Spec->catfile($root, 'logs');
    my $conf_dir = File::Spec->catfile($root, 'conf');

    # The full set Util.pm:601-615 derives from $ServRoot. Missing one leaves
    # this process reading or writing a path under the OLD port's servroot.
    ## no critic (Variables::ProhibitPackageVars)
    $Test::Nginx::Util::ServRoot   = $root;
    $Test::Nginx::Util::LogDir     = $log_dir;
    $Test::Nginx::Util::ErrLogFile = File::Spec->catfile($log_dir, 'error.log');
    $Test::Nginx::Util::AccLogFile = File::Spec->catfile($log_dir, 'access.log');
    $Test::Nginx::Util::HtmlDir    = File::Spec->catfile($root, 'html');
    $Test::Nginx::Util::ConfDir    = $conf_dir;
    $Test::Nginx::Util::ConfFile   = File::Spec->catfile($conf_dir, 'nginx.conf');
    $Test::Nginx::Util::PidFile    = File::Spec->catfile($log_dir, 'nginx.pid');
    $Test::Nginx::Util::CacheDir   = File::Spec->catfile($root, 'cache');
    ## use critic

    # NOT local: nginx is started later, from a different scope, and must
    # inherit this. A localised assignment would revert before it ever reached
    # the child, leaving it on the old servroot -- the exact bug this fixes.
    ## no critic (Variables::RequireLocalizedPunctuationVars)
    $ENV{TEST_NGINX_SERVER_ROOT} = $root;
    ## use critic

    return;
}

# Re-draw from the same range Util.pm uses (1988 .. 65534, see gen_rand_port)
# until a pair binds. Leaves $ServerPort untouched when it is already good, so
# the common case keeps the scaffold's own choice and its servroot_<port> name.
#
# This closes the TOCTOU window no further than gen_rand_port does -- the
# sockets are closed before nginx starts either way. It removes the systematic
# blind spot (wrong address family, unprobed origin port), not the last
# microsecond of race, which is why the value is in the re-draw: a collision
# now costs one more draw instead of bailing 41 files.
sub _ensure_bindable_port {
    my $port = server_port();

    return if _pair_is_free($port);

    for (1 .. 1000) {
        my $candidate = int(rand 63546) + 1988;    # leaves room for +1
        next unless _pair_is_free($candidate);

        Test::Nginx::Util::server_port($candidate);
        Test::Nginx::Util::server_port_for_client($candidate);
        _repoint_servroot($candidate);
        return;
    }

    die "CacheTurbo: no bindable (port, port+1) pair after 1000 draws\n";
}

_ensure_bindable_port();

# The origin listens BESIDE nginx, on $ServerPort + 1.
#
# It must not be a fixed number. Under TEST_NGINX_RANDOMIZE (which is what
# makes `prove -jN` safe -- it gives every parallel job its own random
# $ServerPort and its own t/servroot_<port>/) a hardcoded origin port is the
# ONE thing still shared between jobs, and two jobs racing it fail with
# "bind() to 127.0.0.1:<port> failed (98: Address already in use)".
#
# +1 is checked, not assumed: _pair_is_free() above proves this exact port
# bindable before any nginx starts. Test::Nginx reserves $ServerPort+1..+3 for
# stream_server_config blocks and this suite declares none, so the window is
# free for the origin to claim.
sub ct_origin_port { return server_port() + 1 }

# The origin every preset file proxies to. Lives in the same nginx as the code
# under test -- a separate origin process would be a second fixture to start,
# supervise and tear down per file, for no gain: nothing here needs the origin
# to fail, stall or be counted (those cases stay in ci/tools/test_runtime.py).
#
# The body is unique per origin contact and echoes the request Cookie -- see the
# comments on the location below for why each half is load-bearing.
sub ct_http_config {
    my $op = ct_origin_port();
    return <<"EOC";
    cache_turbo_zone main 16m;

    map \$host \$ct_unused {
        default "";
    }

    server {
        listen       127.0.0.1:$op;
        server_name  origin;

        # The body must be unique per origin CONTACT, so that "this response
        # came from the cache" and "this response is a fresh origin hit" are
        # distinguishable by content alone, and a wrongly-SHARED entry is
        # visible as a repeated value.
        #
        # \$connection alone is not enough (a keep-alive connection serves
        # several requests) and \$connection_requests alone is not enough (two
        # separate connections both start at 1). The PAIR is unique: within one
        # connection the counter increments, and across connections the
        # connection number differs. \$msec breaks the remaining tie if a
        # connection number is ever reused within the same worker run.
        # The body also ECHOES the request's Cookie header. That is what makes a
        # key-cookie assertion provable from a single response: if a request
        # carrying `xf_language_id=de` is wrongly served the `=en` entry, the
        # cached body it gets back still says `en`, and a `--- response_body_like`
        # matching `de` fails. Without the echo, a shared entry and a correctly
        # separate one are indistinguishable by content.
        location / {
            add_header Cache-Control "public, max-age=30" always;
            return 200 "origin:\$request_uri:\$connection:\$connection_requests:\$msec:ck=\$http_cookie\n";
        }
    }
EOC
}

# One cache_turbo location. `cache_turbo_key $uri` matches the key the Python
# suite used for these same cases: the cache key is the PATH ONLY, so a query
# argument cannot split the entry by itself. That is load-bearing -- an arg-rule
# test asserts a BYPASS, and if the query string were in the key the request
# would simply be a MISS on a fresh entry and the assertion would pass with the
# rule removed.
sub ct_location {
    my (%arg) = @_;
    my $op      = ct_origin_port();
    my $path    = $arg{path}    // die "ct_location: path required";
    my $backend = $arg{backend} // die "ct_location: backend required";
    my $extra   = $arg{extra}   // '';

    # $extra is interpolated at column 0 immediately before proxy_pass, so a
    # value with no trailing newline would weld the two together into
    # "...;            proxy_pass ...". nginx forgives that only when $extra
    # happens to end in ';'; anything else silently corrupts the config into a
    # directive nobody wrote. Normalise here rather than trusting every future
    # caller to remember the newline.
    $extra .= "\n" if length $extra && $extra !~ /\n\z/;

    return <<"EOL";
        location $path {
            cache_turbo         main;
            cache_turbo_backend $backend;
            cache_turbo_key     \$uri;
            cache_turbo_valid   30s;
$extra            proxy_pass http://127.0.0.1:$op/;
        }
EOL
}

# Assemble a full `--- config` from a list of ct_location() specs.
sub ct_config {
    # Unpacked before use rather than mapped over @_ directly: inside the map
    # block @_ would be the BLOCK's arguments, not this sub's, so the current
    # form works only because map happens not to rebind it. Naming the list
    # makes that independent of that detail (perlcritic Subroutines::
    # RequireArgUnpacking, PBP p.178).
    my (@specs) = @_;
    return join '', map { ct_location(%$_) } @specs;
}

1;
