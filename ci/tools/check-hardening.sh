#!/usr/bin/env bash
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# Hardening property check for a built ELF shared object.
#   check-hardening.sh <file.so>
#
# Two independent opinions must both pass, so neither a missing nor a changed
# checksec can let a weak binary through:
#   1. readelf/nm (deterministic, binutils)
#   2. checksec --output=json (cross-check; a missing checksec is a FAILURE)
#
# Properties, each named in the failure output as "MISSING <name>":
#   RELRO     PT_GNU_RELRO present AND BIND_NOW (full RELRO)
#   canary    undefined __stack_chk_fail (stack protector in use)
#   NX        PT_GNU_STACK present and not executable
#   FORTIFY   at least one undefined *_chk symbol (flag alone is not proof)
#   RWX       no PT_LOAD segment that is both writable and executable
#   execstack PT_GNU_STACK absent (defaults to exec) or flagged E
#
# Exit 0 all present, 1 on any missing property, 2 on usage/tool errors.
# Output is one "ok <name>" / "MISSING <name>: <why>" line per property.

set -euo pipefail

if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
    echo "usage: check-hardening.sh <file.so>" >&2
    exit 2
fi
so="$1"
for t in readelf nm; do
    command -v "$t" >/dev/null 2>&1 || { echo "check-hardening: $t not found" >&2; exit 2; }
done
if ! command -v checksec >/dev/null 2>&1; then
    echo "check-hardening: FAIL checksec not installed (a missing checksec is a failure, not a skip)" >&2
    exit 2
fi
echo "checksec-version: $(checksec --version 2>&1 | head -1)"

fail=0
ok() { echo "ok $1"; }
miss() { echo "MISSING $1: $2"; fail=1; }

phdrs="$(LC_ALL=C readelf -W -l "$so")"
dyn="$(LC_ALL=C readelf -W -d "$so")"
syms="$(LC_ALL=C nm -D --undefined-only "$so" 2>/dev/null || true)"

# RELRO: segment plus immediate binding.
if ! grep -q 'GNU_RELRO' <<<"$phdrs"; then
    miss RELRO "no PT_GNU_RELRO segment"
elif ! grep -Eq '\((BIND_NOW)\)|FLAGS.*BIND_NOW|FLAGS_1.*NOW' <<<"$dyn"; then
    miss RELRO "PT_GNU_RELRO present but no BIND_NOW (partial RELRO; link with -Wl,-z,now)"
else
    ok RELRO
fi

if grep -Eq '(^|[[:space:]])__stack_chk_fail($|@)' <<<"$syms"; then
    ok canary
else
    miss canary "no __stack_chk_fail reference (build with -fstack-protector-strong)"
fi

stack_line="$(grep 'GNU_STACK' <<<"$phdrs" || true)"
if [ -z "$stack_line" ]; then
    miss NX "no PT_GNU_STACK segment (stack defaults to executable)"
    miss execstack "no PT_GNU_STACK segment"
elif grep -Eq '[[:space:]]RWE[[:space:]]' <<<"$stack_line"; then
    miss NX "PT_GNU_STACK is executable"
    miss execstack "PT_GNU_STACK flags RWE"
else
    ok NX
    ok execstack
fi

if grep -E '^[[:space:]]*LOAD' <<<"$phdrs" | grep -q 'RWE'; then
    miss RWX "a PT_LOAD segment is writable and executable"
else
    ok RWX
fi

nchk="$(grep -Ec '(^|[[:space:]])__[A-Za-z0-9_]+_chk($|@)' <<<"$syms" || true)"
if [ "$nchk" -gt 0 ]; then
    ok "FORTIFY ($nchk *_chk symbols)"
else
    miss FORTIFY "no *_chk symbols (build with -O2 -D_FORTIFY_SOURCE=3)"
fi

# checksec cross-check. Its JSON is parsed strictly: an empty or unparsable
# answer is a failure, never a pass.
cs_json="$(checksec --output=json --file="$so" 2>/dev/null || true)"
cs_out="$(CS_JSON="$cs_json" SO="$so" python3 -I -c '
import json, os, sys
try:
    d = json.loads(os.environ["CS_JSON"])
    e = d[os.environ["SO"]]
except Exception as exc:
    print("unparsable checksec output: %s" % exc)
    sys.exit(3)
bad = []
if e.get("relro") != "full": bad.append("RELRO=%s" % e.get("relro"))
if e.get("canary") != "yes": bad.append("canary=%s" % e.get("canary"))
if e.get("nx") != "yes": bad.append("NX=%s" % e.get("nx"))
if e.get("fortify_source") != "yes": bad.append("FORTIFY=%s" % e.get("fortify_source"))
print(" ".join(bad) if bad else "all-ok")
sys.exit(1 if bad else 0)
' 2>&1)" && cs_rc=0 || cs_rc=$?
if [ "$cs_rc" -eq 0 ] && [ "$cs_out" = all-ok ]; then
    ok "checksec (full RELRO, canary, NX, FORTIFY)"
else
    miss checksec "$cs_out"
fi

if [ "$fail" -ne 0 ]; then
    echo "check-hardening: FAIL $so" >&2
    exit 1
fi
echo "check-hardening: PASS $so"
