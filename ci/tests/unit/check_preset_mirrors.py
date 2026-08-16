#!/usr/bin/env python3
"""Keep auto-classify test preset tables exact with the C registry.

The runtime tests deliberately keep their locations and needles as readable
Python tables.  This guard makes their hand-maintained needle coverage an exact
projection of every populated cookie/argument row in the shipped C preset
registry, while separately proving each chosen test location is rendered by
the nginx test configuration.
"""

from __future__ import annotations

import ast
import importlib.util
import pathlib
import re
import sys
from typing import Any


def fail(message: str) -> None:
    print(f"✗ {message}", file=sys.stderr)
    raise SystemExit(1)


def c_string(value: str) -> str:
    """Decode the small C-string subset used by the static preset arrays."""
    try:
        return ast.literal_eval(f'"{value}"')
    except (SyntaxError, ValueError) as exc:
        fail(f"cannot decode C string literal {value!r}: {exc}")


def c_arrays(source: str) -> dict[str, list[str]]:
    source = re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.S)
    arrays: dict[str, list[str]] = {}
    pattern = re.compile(
        r"static\s+const\s+char\s+\*const\s+(ct_[a-z0-9_]+)\[\]"
        r"\s*=\s*\{(.*?)\};", re.S)
    for match in pattern.finditer(source):
        name, body = match.groups()
        values = [c_string(value) for value in re.findall(
            r'"((?:\\.|[^"\\])*)"', body)]
        residue = re.sub(r'"(?:\\.|[^"\\])*"|NULL|[\s,]', "", body)
        if residue:
            fail(f"unsupported token in C preset array {name}: {residue!r}")
        if "NULL" not in body:
            fail(f"C preset array {name} lacks its NULL terminator")
        arrays[name] = values
    if not arrays:
        fail("could not locate any C preset arrays")
    return arrays


def c_registry(source: str, arrays: dict[str, list[str]]) -> tuple[
        dict[str, list[str]], dict[str, list[str]]]:
    source = re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.S)
    registry = re.search(
        r"ngx_http_cache_turbo_presets\[\]\s*=\s*\{(.*?)\n\};", source,
        re.S)
    if not registry:
        fail("could not locate ngx_http_cache_turbo_presets[]")

    pattern = re.compile(
        r"\{\s*NGX_HTTP_CACHE_TURBO_BACKEND_([A-Z0-9]+)\s*,\s*"
        r"(ct_[a-z0-9_]+_cookies)\s*,\s*ct_[a-z0-9_]+_uris\s*,\s*"
        r"(ct_[a-z0-9_]+_args)\s*,", re.S)
    cookies: dict[str, list[str]] = {}
    args: dict[str, list[str]] = {}
    for match in pattern.finditer(registry.group(1)):
        preset, cookie_array, arg_array = match.groups()
        name = preset.lower()
        if name in cookies or name in args:
            fail(f"duplicate C preset registry row for {name}")
        try:
            cookie_values, arg_values = arrays[cookie_array], arrays[arg_array]
        except KeyError as exc:
            fail(f"C preset registry {name} references missing array {exc.args[0]}")
        if cookie_values:
            cookies[name] = cookie_values
        if arg_values:
            args[name] = arg_values

    if not cookies or not args:
        fail("C preset registry did not yield populated cookie and argument rows")
    return cookies, args


def python_table(path: pathlib.Path, name: str) -> dict[str, tuple[str, list[str]]]:
    try:
        tree = ast.parse(path.read_text(), filename=str(path))
    except (OSError, SyntaxError) as exc:
        fail(f"cannot parse Python mirror {path}: {exc}")
    values: list[ast.AST] = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if any(isinstance(target, ast.Name) and target.id == name
                   for target in node.targets):
                values.append(node.value)
    if len(values) != 1:
        fail(f"expected exactly one {name} assignment in {path}, found {len(values)}")
    try:
        table: Any = ast.literal_eval(values[0])
    except ValueError as exc:
        fail(f"{name} in {path} must remain a literal table: {exc}")
    if not isinstance(table, dict):
        fail(f"{name} in {path} is not a dict literal")
    for preset, row in table.items():
        if (not isinstance(preset, str) or not isinstance(row, tuple)
                or len(row) != 2 or not isinstance(row[0], str)
                or not isinstance(row[1], list)
                or not all(isinstance(needle, str) for needle in row[1])):
            fail(f"{name} row for {preset!r} must be (location, [string needles])")
    return table


def rendered_locations(path: pathlib.Path) -> set[str]:
    spec = importlib.util.spec_from_file_location("preset_mirror_nginx_config", path)
    if spec is None or spec.loader is None:
        fail(f"cannot load rendered nginx config builder {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rendered = module.nginx_config(pathlib.Path("/tmp/cache-turbo-preset-mirror"),
                                   18080, None, 18091, 1)
    return set(re.findall(r"(?m)^\s*location\s+(?:=\s+)?([^\s{]+)", rendered))


def compare(kind: str, source: dict[str, list[str]],
            mirror: dict[str, tuple[str, list[str]]]) -> None:
    source_names, mirror_names = set(source), set(mirror)
    if source_names != mirror_names:
        only_source = ", ".join(sorted(source_names - mirror_names)) or "none"
        only_mirror = ", ".join(sorted(mirror_names - source_names)) or "none"
        fail(f"{kind} mirror rows differ: source-only={only_source}; "
             f"mirror-only={only_mirror}")
    for preset in sorted(source):
        source_needles, mirror_needles = source[preset], mirror[preset][1]
        if source_needles != mirror_needles:
            source_only = [n for n in source_needles if n not in mirror_needles]
            mirror_only = [n for n in mirror_needles if n not in source_needles]
            fail(f"{kind} needles differ for {preset}: source-only={source_only}; "
                 f"mirror-only={mirror_only}")


def check_locations(kind: str, table: dict[str, tuple[str, list[str]]],
                    locations: set[str]) -> None:
    for preset, (location, _) in sorted(table.items()):
        if location not in locations:
            fail(f"{kind} test location for {preset} does not exist in rendered "
                 f"config: {location}")


def main() -> None:
    if len(sys.argv) != 4:
        fail("usage: check_preset_mirrors.py <module.c> <areas/core.py> "
             "<nginx_config.py>")
    c_path, core_path, config_path = map(pathlib.Path, sys.argv[1:])
    source = c_path.read_text()
    cookies, args = c_registry(source, c_arrays(source))
    cookie_mirror = python_table(core_path, "_COOKIE_NEEDLE_TABLE")
    arg_mirror = python_table(core_path, "_ARG_NEEDLE_TABLE")

    compare("cookie", cookies, cookie_mirror)
    compare("argument", args, arg_mirror)
    locations = rendered_locations(config_path)
    check_locations("cookie", cookie_mirror, locations)
    check_locations("argument", arg_mirror, locations)
    print("✓ auto-classify preset test mirrors match C registry "
          f"({len(cookies)} cookie rows/{sum(map(len, cookies.values()))} needles; "
          f"{len(args)} argument rows/{sum(map(len, args.values()))} needles; "
          f"{len(locations)} rendered locations)")


if __name__ == "__main__":
    main()
