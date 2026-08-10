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

use Test::Nginx::Util qw( server_port );

use Exporter 'import';
our @EXPORT_OK = qw( ct_http_config ct_location ct_config ct_origin_port );

# The origin listens BESIDE nginx, on a port derived from the one Test::Nginx
# picked for this process.
#
# It must not be a fixed number. Under TEST_NGINX_RANDOMIZE (which is what
# makes `prove -jN` safe -- it gives every parallel job its own random
# $ServerPort and its own t/servroot_<port>/) a hardcoded origin port is the
# ONE thing still shared between jobs, and two jobs racing it fail with
# "bind() to 127.0.0.1:<port> failed (98: Address already in use)".
#
# +1 is safe: gen_rand_port() only hands out a port it could actually bind, and
# Test::Nginx itself reserves $ServerPort+1..+3 for its stream_server_config
# blocks (Util.pm gen_rand_port, "NB: reserved ports for stream_server_config").
# This suite declares no stream servers, so that reserved window is free here.
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
