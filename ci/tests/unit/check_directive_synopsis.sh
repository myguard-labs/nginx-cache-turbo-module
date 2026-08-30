#!/usr/bin/env bash
set -euo pipefail

root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
python3 - "$root" "${CC:-cc}" <<'PY'
import pathlib, re, shlex, subprocess, sys, tempfile

root = pathlib.Path(sys.argv[1]); cc = sys.argv[2]
module = (root / "src/ngx_http_cache_turbo_module.c").read_text()
conf = (root / "src/ngx_http_cache_turbo_conf.c").read_text()
header = (root / "src/ngx_http_cache_turbo_module.h").read_text()
readme = (root / "README.md").read_text()

def require(pattern, text, label, flags=0):
    match = re.search(pattern, text, flags)
    if not match:
        raise SystemExit(f"directive synopsis: cannot extract {label}")
    return match.group(0)

def split_pipes(line):
    cells, start, escaped = [], 0, False
    for i, char in enumerate(line):
        if char == "|" and not escaped:
            cells.append(line[start:i]); start = i + 1
        escaped = char == "\\" and not escaped
        if char != "\\": escaped = False
    cells.append(line[start:])
    return [cell.strip() for cell in cells]

# Preserve the existing completeness half of this gate.
registered = list(dict.fromkeys(re.findall(
    r'ngx_string\("(cache_turbo(?:_[^"]+)?)"\)', module)))
internal = {"cache_turbo_probe", "cache_turbo_normalized_args",
            "cache_turbo_active", "cache_turbo_status", "cache_turbo_serve_reason"}
registered = [n for n in registered
              if not n.startswith("cache_turbo_test_") and n not in internal]
synopsis = readme.split("## Directive synopsis", 1)[1].split("\n## ", 1)[0]
rows = {}
for line in synopsis.splitlines():
    if line.startswith("| `"):
        cells = split_pipes(line)
        rows[cells[1].strip("`").split()[0]] = cells
missing = [n for n in registered if n not in rows]
if missing: raise SystemExit("directive synopsis missing: " + ", ".join(missing))
for name in registered:
    if len(rows[name]) < 5 or not rows[name][3]:
        raise SystemExit("directive synopsis row has empty Default cell: " + name)
reference = readme.split("## Every directive in one place (full syntax)", 1)[1]
reference = reference.split("```nginx", 1)[1].split("```", 1)[0]
missing_reference = [n for n in registered if not re.search(
    r"^\s*#?\s*" + re.escape(n) + r"(?:\s|$)", reference, re.M)]
if missing_reference:
    raise SystemExit("full-reference config missing: " + ", ".join(missing_reference))
if not re.search(r"^\s*cache_turbo_keep_stale\s+24h\s*;", reference, re.M):
    raise SystemExit("full-reference default drift: cache_turbo_keep_stale must be 24h")

# Compile the production-owned selector, physical array, and effective-field
# fallbacks. Values come from C semantics, never row comments or numeric labels.
band_type = require(r"typedef struct\s*\{.*?\}\s*ngx_http_cache_turbo_band_t\s*;",
                    header, "preset band type", re.S)
preset_defines = "\n".join(require(
    rf"^#define\s+NGX_HTTP_CACHE_TURBO_PRESET_{name}\s+.+$", header,
    f"{name.lower()} selector", re.M)
    for name in ("CONSERVATIVE", "BALANCED", "AGGRESSIVE", "MICRO", "DEFAULT"))
band_array = require(
    r"const\s+ngx_http_cache_turbo_band_t\s+ngx_http_cache_turbo_bands\[\]"
    r"\s*=\s*\{.*?\n\};", module, "physical preset band array", re.S)
selector = require(
    r"p\s*=\s*\(conf->preset\s*==\s*NGX_CONF_UNSET\)\s*"
    r"\?\s*NGX_HTTP_CACHE_TURBO_PRESET_DEFAULT\s*:\s*conf->preset\s*;",
    conf, "default preset selector", re.S)
band_lookup = require(r"band\s*=\s*&ngx_http_cache_turbo_bands\[p\]\s*;",
                      conf, "preset band lookup", re.S)
fallbacks = [require(
    rf"conf->{field}\s*=\s*\(conf->{field}_raw\s*==\s*NGX_CONF_UNSET\)"
    rf"\s*\?\s*band->[a-z_]+\s*:\s*conf->{field}_raw\s*;",
    conf, f"{field} band fallback", re.S)
    for field in ("valid", "beta", "lock_ttl", "stale_mult", "min_uses")]

program = f'''\
#include <stdio.h>
typedef long time_t;
typedef long ngx_int_t;
#define NGX_CONF_UNSET (-1)
{preset_defines}
{band_type}
{band_array}
typedef struct {{
 ngx_int_t preset; time_t valid_raw, lock_ttl_raw;
 ngx_int_t beta_raw, stale_mult_raw, min_uses_raw;
 time_t valid, lock_ttl; ngx_int_t beta, stale_mult, min_uses;
}} test_loc_conf_t;
static void emit_default(void) {{
 test_loc_conf_t s = {{ .preset=NGX_CONF_UNSET, .valid_raw=NGX_CONF_UNSET,
  .beta_raw=NGX_CONF_UNSET, .lock_ttl_raw=NGX_CONF_UNSET,
  .stale_mult_raw=NGX_CONF_UNSET, .min_uses_raw=NGX_CONF_UNSET }};
 test_loc_conf_t *conf=&s; ngx_int_t p;
 const ngx_http_cache_turbo_band_t *band;
 {selector} {band_lookup} {' '.join(fallbacks)}
 printf("default %ld %ld %ld %ld %ld %ld\\n", (long)p, (long)conf->valid,
  (long)conf->beta, (long)conf->lock_ttl, (long)conf->stale_mult,
  (long)conf->min_uses);
}}
static void emit_band(const char *name, ngx_int_t p) {{
 const ngx_http_cache_turbo_band_t *band=&ngx_http_cache_turbo_bands[p];
 printf("band %s %ld %ld %ld %ld %ld\\n", name, (long)band->valid,
  (long)band->beta, (long)band->lock_ttl, (long)band->stale_mult,
  (long)band->min_uses);
}}
int main(void) {{
 emit_band("micro", NGX_HTTP_CACHE_TURBO_PRESET_MICRO);
 emit_band("conservative", NGX_HTTP_CACHE_TURBO_PRESET_CONSERVATIVE);
 emit_band("balanced", NGX_HTTP_CACHE_TURBO_PRESET_BALANCED);
 emit_band("aggressive", NGX_HTTP_CACHE_TURBO_PRESET_AGGRESSIVE);
 emit_default(); return 0;
}}
'''
with tempfile.TemporaryDirectory(prefix="cache-turbo-defaults-") as tmp:
    source = pathlib.Path(tmp) / "defaults.c"; binary = pathlib.Path(tmp) / "defaults"
    source.write_text(program)
    built = subprocess.run([*shlex.split(cc), "-std=c99", "-Wall", "-Wextra", "-Werror",
                            str(source), "-o", str(binary)],
                           text=True, capture_output=True)
    if built.returncode:
        sys.stderr.write(built.stdout + built.stderr)
        raise SystemExit("directive synopsis: compiled default emitter failed")
    emitted = subprocess.check_output([str(binary)], text=True).splitlines()

actual_bands, actual_default = {}, None
for line in emitted:
    parts = line.split()
    if parts[0] == "band": actual_bands[parts[1]] = tuple(map(int, parts[2:]))
    elif parts[0] == "default": actual_default = tuple(map(int, parts[1:]))

def emit(candidate, control):
    """Compile a mutation with the same isolated default-emission semantics."""
    with tempfile.TemporaryDirectory(prefix="cache-turbo-defaults-") as tmp:
        source = pathlib.Path(tmp) / "defaults.c"; binary = pathlib.Path(tmp) / "defaults"
        source.write_text(candidate)
        built = subprocess.run([*shlex.split(cc), "-std=c99", "-Wall", "-Wextra", "-Werror",
                                str(source), "-o", str(binary)],
                               text=True, capture_output=True, check=False)
        if built.returncode:
            sys.stderr.write(built.stdout + built.stderr)
            raise SystemExit(f"directive synopsis mutation is not compile-safe: {control}")
        lines = subprocess.check_output([str(binary)], text=True).splitlines()
    bands, default = {}, None
    for line in lines:
        parts = line.split()
        if parts[0] == "band": bands[parts[1]] = tuple(map(int, parts[2:]))
        elif parts[0] == "default": default = tuple(map(int, parts[1:]))
    return bands, default

preset_section = readme.split("## Presets (pick a vibe, skip the knobs)", 1)[1]
table_lines = [line for line in preset_section.splitlines() if line.startswith("|")][:7]
matrix = [split_pipes(line) for line in table_lines]
if len(matrix) != 7:
    raise SystemExit("directive synopsis: README preset matrix shape changed")
names = tuple(c.replace("`", "").replace(" (default)", "") for c in matrix[0][2:6])
converters = (lambda v:int(v.removesuffix("s")), lambda v:int(v),
              lambda v:int(v.removesuffix("s")), lambda v:int(v.removeprefix("×")),
              lambda v:int(v.replace("**", "")))
documented = {name: tuple(convert(matrix[row][col])
                          for row, convert in enumerate(converters, 2))
              for col, name in enumerate(names, 2)}
if actual_bands != documented:
    raise SystemExit(f"preset matrix drift: compiled={actual_bands} README={documented}")
if actual_default is None:
    raise SystemExit("directive synopsis: default emitter produced no result")
default_index, *effective = actual_default
indexes = {"conservative":1, "balanced":2, "aggressive":3, "micro":4}
default_name = next((name for name, index in indexes.items()
                     if index == default_index), None)
if default_name != "balanced":
    raise SystemExit(f"cache_turbo_preset default drift: compiled={default_name}")

expected_cells = {
 "cache_turbo_preset":"`balanced`", "cache_turbo_valid":"preset (`60s`)",
 "cache_turbo_beta":"preset (`1000`)", "cache_turbo_lock_ttl":"preset (`5s`)",
 "cache_turbo_stale_mult":"preset (`4` balanced)",
 "cache_turbo_min_uses":"preset (`1`, `2` aggressive)"}
for name, expected in expected_cells.items():
    if rows[name][3] != expected:
        raise SystemExit(f"{name} Default cell drift: {rows[name][3]!r} != {expected!r}")
if tuple(effective) != documented[default_name]:
    raise SystemExit(f"effective preset fallback drift: compiled={tuple(effective)} "
                     f"README={documented[default_name]}")

def reject(candidate, control):
    bands, default = emit(candidate, control)
    if bands != documented:
        print(f"directive synopsis mutation red: {control}: preset matrix drift")
        return
    if default is None:
        raise SystemExit(f"directive synopsis mutation survived: {control}")
    index, *values = default
    name = next((candidate for candidate, value in indexes.items() if value == index), None)
    if name != "balanced":
        print(f"directive synopsis mutation red: {control}: cache_turbo_preset default drift")
        return
    if tuple(values) != documented[name]:
        print(f"directive synopsis mutation red: {control}: effective preset fallback drift")
        return
    raise SystemExit(f"directive synopsis mutation survived: {control}")

def replace_once(text, old, new, control):
    if text.count(old) != 1:
        raise SystemExit(f"directive synopsis mutation fixture missing: {control}")
    return text.replace(old, new, 1)

# These controls keep README untouched and recompile the extracted production
# path. They prove the gate observes physical data/order and effective wiring,
# not comments or a source-label convention.
physical_rows = list(re.finditer(r"(\{)([^{}]*)(\})", band_array))
if len(physical_rows) != 5:
    raise SystemExit("directive synopsis mutation fixture missing: preset rows")
balanced, aggressive = physical_rows[2], physical_rows[3]
swapped_array = (band_array[:balanced.start(2)] + aggressive.group(2)
                 + band_array[balanced.end(2):aggressive.start(2)]
                 + balanced.group(2) + band_array[aggressive.end(2):])
reject(replace_once(program, band_array, swapped_array, "physical preset row order"),
       "physical preset row order")

aggressive_default = replace_once(
    preset_defines,
    "NGX_HTTP_CACHE_TURBO_PRESET_DEFAULT  NGX_HTTP_CACHE_TURBO_PRESET_BALANCED",
    "NGX_HTTP_CACHE_TURBO_PRESET_DEFAULT  NGX_HTTP_CACHE_TURBO_PRESET_AGGRESSIVE",
    "default preset selector")
reject(replace_once(program, preset_defines, aggressive_default, "default preset selector"),
       "default preset selector")

fallback_fields = ("valid", "beta", "lock_ttl", "stale_mult", "min_uses")
for field, replacement, fallback in zip(
        fallback_fields, fallback_fields[1:] + fallback_fields[:1], fallbacks):
    rewired = replace_once(fallback, f"band->{field}", f"band->{replacement}",
                           f"{field} band fallback")
    reject(replace_once(program, fallback, rewired, f"{field} band fallback"),
           f"{field} band fallback")
print(f"OK: {len(registered)} registered production directives have synopsis rows; "
      "compiled preset defaults match the exact README cells")
PY
