#!/usr/bin/env python3
"""Check the descriptor budget's frozen schema, type widths and allocation path.

Bounds and bytes share one descriptor walk; there is no prose estimate or
hand-counted multiplier. Executable maxima, escaping and one-byte-short controls
live in ci/tests/unit/test_stats_schema.py and are run by the unit CI lane.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    schema = (ROOT / "src/ngx_http_cache_turbo_stats_schema.h").read_text()
    admin = (ROOT / "src/ngx_http_cache_turbo_admin.c").read_text()
    contract = json.loads((ROOT / "ci/tests/stats-contract.json").read_text())
    failures = []
    literal = r'"(?:[^"\\]|\\.)*"'
    strings = "(" + literal + r"(?:\s*" + literal + ")*)"
    pattern = (r'\{ ngx_string\(' + strings + r'\),\s*ngx_string\(' + strings
               + r'\),\s*ngx_string\(' + strings + r'\),\s*CT_STATS_(\w+),\s*'
               r'offsetof\(ngx_http_cache_turbo_stats_t, (\w+)\), (\d+) \}')
    try:
        rows = [tuple("".join(json.loads(token) for token in re.findall(literal, value))
                      for value in row[:3]) + row[3:]
                for row in re.findall(pattern, schema)]
    except json.JSONDecodeError:
        print("lint-admin-buffer-budget: unsupported descriptor string escape", file=sys.stderr)
        return 1
    keys = [row[0] for row in rows] + ["lock_ttl"]
    if keys != contract["json_keys"]:
        failures.append("JSON descriptor names/order/count differ from frozen contract")
    families = []
    for key, name, help_text, kind, member, _order in sorted(rows, key=lambda row: int(row[5])):
        if member != key:
            failures.append(f"{key}: snapshot member mismatch: {member}")
        allowed_kinds = ("STATE",) if key == "breaker_state" else ("COUNTER", "GAUGE")
        if kind not in allowed_kinds:
            failures.append(f"{key}: unrecognized descriptor type {kind}")
        families.append({"name": name, "help": help_text,
                         "type": "counter" if kind == "COUNTER" else "gauge"})
    if families != contract["prometheus_families"]:
        failures.append("Prometheus descriptors differ from frozen names/HELP/types/order")
    if sorted(int(row[5]) for row in rows) != list(range(len(rows))):
        failures.append("Prometheus descriptor order must be a dense unique permutation")
    # Bind the typed time-only descriptor and full-width measurement branches.
    required = (
        '{ ngx_string("lock_ttl"), ngx_null_string, ngx_null_string,\n      CT_STATS_TIME, 0, 0 }',
        'ngx_http_cache_turbo_stats_write(&w, NULL, NGX_TIME_T_LEN);',
        'ngx_http_cache_turbo_stats_write(&w, NULL, NGX_ATOMIC_T_LEN);',
        'ngx_http_cache_turbo_stats_write(&w, NULL, sizeof("half-open") - 1);',
        'len > w->capacity - w->len',
        'ngx_http_cache_turbo_stats_escape(&w, zone, 0);',
    )
    for text in required:
        if text not in schema:
            failures.append(f"missing schema bound invariant: {text}")
    reply = admin[admin.index("ngx_http_cache_turbo_admin_stats_reply("):
                  admin.index("/* Stats dispatch.")]
    for text in ("NULL, (size_t) -1, &capacity)", "ngx_pnalloc(r->pool, capacity)",
                 "body.data, capacity, &body.len)"):
        if text not in reply:
            failures.append(f"admin must measure, allocate and render the same bound: {text}")
    if re.search(r"capacity\s*[-+*/]?=|capacity\s*(?:--|\+\+)", reply):
        failures.append("admin must not adjust the derived capacity")
    for failure in failures:
        print(f"lint-admin-buffer-budget: {failure}", file=sys.stderr)
    if failures:
        return 1
    print(f"lint-admin-buffer-budget: OK ({len(keys)} JSON / {len(rows)} Prometheus descriptors; derived bounds)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
