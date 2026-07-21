#!/usr/bin/env bash
# Reproducible tool inventory for this repo's local-only tooling
# (ci/tools/bench.sh, ci/tools/soak.sh). Not part of the Debian package build.
#
# wrk 4.1.0-4+b1 (Debian package) — HTTP load generator used by ci/tools/bench.sh.
#   apt-get install wrk
#
# gawk 1:5.2.1-2 (Debian package) — ci/tools/bench.sh PASSES>1 median/min/max
#   uses gawk's asort(); the default /usr/bin/awk (mawk) lacks it.
#   apt-get install gawk
#
# time 1.9-0.2 (Debian package) — provides /usr/bin/time -v, used by
#   ci/tools/bench.sh to record wrk's own CPU% per pass (contention
#   measurement: tells a client-side wrk bottleneck apart from a real
#   server-side one). Optional: bench.sh degrades to no CPU reading (0%,
#   never MASKED) if /usr/bin/time is absent.
#   apt-get install time
