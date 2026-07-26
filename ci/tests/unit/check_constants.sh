#!/usr/bin/env bash
#
# The unit-test shim (ngx_shim_math.h) re-defines the fixed-point constants the
# math units use, because it deliberately does NOT include the real module.h.
# If those drift from src/ngx_http_cache_turbo_module.h the tests would assert
# against stale numbers and pass while production changed. This guard extracts
# each constant's value from BOTH files and fails on any mismatch.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HDR="$DIR/../../../src/ngx_http_cache_turbo_module.h"
SHIM="$DIR/ngx_shim_math.h"

CONSTS=(
    NGX_HTTP_CACHE_TURBO_STALE_MULTIPLIER
    NGX_HTTP_CACHE_TURBO_TTL_MAX
    NGX_HTTP_CACHE_TURBO_BETA_MIN
    NGX_HTTP_CACHE_TURBO_BETA_MAX
    NGX_HTTP_CACHE_TURBO_BETA_COST_DIVISOR
    NGX_HTTP_CACHE_TURBO_AT_COST_STRONG_MS
    NGX_HTTP_CACHE_TURBO_AT_COST_MOD_MS
    NGX_HTTP_CACHE_TURBO_AT_MISSES_FLOOR
    NGX_HTTP_CACHE_TURBO_AT_HIT_RATE_CAP
    NGX_HTTP_CACHE_TURBO_AT_CHURN_CAP
    NGX_HTTP_CACHE_TURBO_AT_LOAD_BASE
    NGX_HTTP_CACHE_TURBO_AT_LOAD_MAX
    NGX_HTTP_CACHE_TURBO_AT_LOAD_PER_MS
    NGX_HTTP_CACHE_TURBO_AT_INTERVAL
)

# Pull the value token(s) after `#define <NAME>`, strip trailing block comments
# and surrounding whitespace, and collapse internal spaces so `((time_t)
# 0xFFFFFFFF)` compares equal regardless of spacing.
value_of() {
    local file="$1" name="$2"
    grep -E "^#define[[:space:]]+${name}[[:space:]]" "$file" \
        | head -1 \
        | sed -E "s/^#define[[:space:]]+${name}[[:space:]]+//; s|/\*.*\*/||; s|/\*.*||; s/[[:space:]]+/ /g; s/^ //; s/ $//"
}

rc=0
for c in "${CONSTS[@]}"; do
    h="$(value_of "$HDR" "$c")"
    s="$(value_of "$SHIM" "$c")"
    if [ -z "$h" ]; then
        echo "✗ $c not found in module.h" >&2; rc=1; continue
    fi
    if [ -z "$s" ]; then
        echo "✗ $c not found in shim" >&2; rc=1; continue
    fi
    if [ "$h" != "$s" ]; then
        echo "✗ $c drift: module.h='$h' shim='$s'" >&2; rc=1
    fi
done

if [ "$rc" -ne 0 ]; then
    echo "unit-test shim constants drifted from module.h — update ngx_shim_math.h" >&2
    exit 1
fi
echo "✓ unit-test shim constants match module.h (${#CONSTS[@]} checked)"

# ---------------------------------------------------------------------------
# Auto-classify preset bits: src/ngx_http_cache_turbo_module.h vs the FUZZ shim
# (ci/fuzz/ngx_shim_auto.h), which mirrors them by hand.
#
# The fuzz build already fails on a bit that is MISSING from the mirror (an
# undeclared identifier in BACKEND_ALL). It does NOT catch a bit that is present
# but has a DIFFERENT VALUE — that compiles fine and silently fuzzes the wrong
# row. It also cannot catch a preset added to the header alone, since nothing
# there references it. This closes both gaps.
#
# The suffix check is load-bearing, not style: an unsuffixed 0x80000000 is
# `unsigned int`, and `mask & ~BIT` on such an operand clears the high half of
# the 64-bit mask. See the WIDTH note in module.h.
# ---------------------------------------------------------------------------
AUTOSHIM="$DIR/../../fuzz/ngx_shim_auto.h"

if [ ! -f "$AUTOSHIM" ]; then
    echo "✗ fuzz auto-classify shim not found at $AUTOSHIM" >&2
    exit 1
fi

python3 - "$HDR" "$AUTOSHIM" <<'PY'
import re, sys

hdr_path, shim_path = sys.argv[1], sys.argv[2]

def bits(path):
    pat = r'#define\s+NGX_HTTP_CACHE_TURBO_BACKEND_([A-Z0-9]+)\s+(0x[0-9A-Fa-f]+)(ull|ul|u)?\b'
    return {m.group(1): (int(m.group(2), 16), m.group(3) or "<none>")
            for m in re.finditer(pat, open(path).read())}

hdr, shim = bits(hdr_path), bits(shim_path)
rc = 0

if "NONE" not in hdr:
    print("✗ BACKEND_NONE missing from module.h", file=sys.stderr); sys.exit(1)
none_val, none_suf = hdr.pop("NONE")

# 1. every header preset mirrored in the shim, with the same value
for name in sorted(set(hdr) | set(shim)):
    h, s = hdr.get(name), shim.get(name)
    if h is None:
        print(f"✗ {name} in fuzz shim but not module.h", file=sys.stderr); rc = 1
    elif s is None:
        print(f"✗ {name} in module.h but not the fuzz shim — add it there and to "
              f"BACKEND_ALL, or the fuzzer never walks its row", file=sys.stderr); rc = 1
    elif h[0] != s[0]:
        print(f"✗ {name} value drift: module.h={hex(h[0])} shim={hex(s[0])}",
              file=sys.stderr); rc = 1

# 2. every literal is ull (see comment above)
for label, table in (("module.h", {**hdr, "NONE": (none_val, none_suf)}),
                     ("fuzz shim", shim)):
    for name, (val, suf) in sorted(table.items()):
        if suf != "ull":
            print(f"✗ {label} BACKEND_{name}={hex(val)} lacks the ull suffix "
                  f"(is '{suf}') — narrows the mask", file=sys.stderr); rc = 1

# 3. the preset run is gapless from bit 0, and NONE stays clear of it
vals = sorted(v for v, _ in hdr.values())
if vals != [1 << i for i in range(len(vals))]:
    print(f"✗ preset bits are not a gapless run from 0x1: "
          f"{[hex(v) for v in vals]}", file=sys.stderr); rc = 1

allmask = 0
for v, _ in hdr.values():
    allmask |= v
if none_val & allmask:
    print(f"✗ BACKEND_NONE ({hex(none_val)}) collides with the preset run — a "
          f"preset on that bit is invisible to HAS_BACKEND()", file=sys.stderr); rc = 1

# NONE must sit at bit 63, not merely above today's highest preset. Checking
# only for a collision would stay silent until the run actually grew into it —
# i.e. it would first fire on the commit that adds that preset, reporting a
# confusing "invisible preset" instead of "NONE is in the way". This is the
# whole bug this file's widening fixed; pin the invariant, not its symptom.
if none_val != 1 << 63:
    print(f"✗ BACKEND_NONE is {hex(none_val)} (bit {none_val.bit_length() - 1}), "
          f"expected bit 63. Keep the sentinel at the far end so the preset run "
          f"can grow without colliding — see the NONE comment in module.h",
          file=sys.stderr); rc = 1

if rc:
    sys.exit(1)

print(f"✓ auto-classify preset bits match the fuzz shim "
      f"({len(hdr)} presets, gapless, NONE at bit {none_val.bit_length() - 1}, "
      f"{63 - len(hdr)} free)")
PY
