#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Validate a test port band before any fixture binds it. This catches bands
# that overlap the kernel ephemeral range and stale listeners that would make
# a suite talk to an old process.

set -euo pipefail

base="${1:-${TEST_BASE_PORT:-18880}}"
width="${2:-${TEST_PORT_WIDTH:-64}}"

case "$base" in
    ''|*[!0-9]*) echo "ERROR: base port must be numeric, got '$base'" >&2; exit 2 ;;
esac
case "$width" in
    ''|*[!0-9]*) echo "ERROR: width must be numeric, got '$width'" >&2; exit 2 ;;
esac

base=$((10#$base))
width=$((10#$width))
if [ "$width" -lt 1 ]; then
    echo "ERROR: width must be at least 1, got $width" >&2
    exit 2
fi

max=$((base + width - 1))
range_file=/proc/sys/net/ipv4/ip_local_port_range
ephemeral_floor=32768
if [ -r "$range_file" ]; then
    ephemeral_floor="$(awk '{print $1}' "$range_file")"
fi
if [ "$max" -gt 65535 ] || [ "$max" -ge "$ephemeral_floor" ]; then
    echo "ERROR: port band $base..$max is outside the safe listener range (ephemeral floor $ephemeral_floor)" >&2
    exit 1
fi

if ! command -v ss >/dev/null 2>&1; then
    echo "ERROR: ss(8) not found; cannot verify that $base..$max is free" >&2
    exit 2
fi
if ! listeners="$(ss -Hltn 2>&1)"; then
    echo "ERROR: ss(8) failed: $listeners" >&2
    exit 2
fi
busy="$(printf '%s\n' "$listeners" | awk -v lo="$base" -v hi="$max" '
    { n = split($4, a, ":"); p = a[n] + 0; if (p >= lo && p <= hi) print p }
' | sort -un | paste -sd, -)"
if [ -n "$busy" ]; then
    echo "ERROR: ports already listening inside band $base..$max: $busy" >&2
    exit 1
fi

printf '%s\n' "$max"
