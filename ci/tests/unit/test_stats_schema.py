#!/usr/bin/env python3
"""Compile the shipped renderer and compare it to the frozen independent contract."""
import json
import os
import re
import shlex
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def run(output: Path) -> None:
    contract = json.loads((ROOT / "ci/tests/stats-contract.json").read_text())
    module = (ROOT / "src/ngx_http_cache_turbo_module.h").read_text()
    shm = (ROOT / "src/ngx_http_cache_turbo_shm.c").read_text()
    end = module.index("} ngx_http_cache_turbo_stats_t;") + len("} ngx_http_cache_turbo_stats_t;")
    start = module.rindex("typedef struct {", 0, end)
    struct = module[start:end]
    state_start = shm.index("const char *\nngx_http_cache_turbo_shm_breaker_state_str(")
    state_end = shm.index("\n}", state_start) + 2
    constants = "\n".join(re.findall(
        r"^#define NGX_HTTP_CACHE_TURBO_BREAKER_(?:CLOSED|OPEN|HALF_OPEN)\s+\d+.*$",
        module, re.MULTILINE))
    shim = '''#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
typedef unsigned char u_char;
typedef uintptr_t ngx_atomic_uint_t;
typedef uintptr_t ngx_uint_t;
typedef intptr_t ngx_int_t;
typedef intptr_t ngx_flag_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
#define NGX_OK 0
#define NGX_ERROR -1
#define NGX_ATOMIC_T_LEN 20
#define NGX_TIME_T_LEN 20
#define ngx_string(s) {sizeof(s) - 1, (u_char *) s}
#define ngx_null_string {0, NULL}
#define ngx_memcpy memcpy
#define ngx_strlen strlen
'''
    for macro in ("NGX_HTTP_CACHE_TURBO_BREAKER_STATE_BITS",
                  "NGX_HTTP_CACHE_TURBO_BREAKER_STATE_MASK",
                  "ngx_http_cache_turbo_brk_state"):
        module_lines = module.splitlines(keepends=True)
        index = next(i for i, line in enumerate(module_lines)
                     if re.match(r"#define " + macro + r"\b", line))
        while True:
            definition = module_lines[index]
            shim += definition
            if not definition.rstrip().endswith("\\"):
                break
            index += 1
    shim += constants + "\n" + struct + "\n" + shm[state_start:state_end] + "\n"
    shim += "static void seed_stats(ngx_http_cache_turbo_stats_t *st, int maximum) {\n"
    for i, key in enumerate(contract["json_keys"][:-1]):
        shim += f"st->{key} = maximum ? (ngx_atomic_uint_t) -1 : {i + 1};\n"
    shim += "}\n"
    (output / "stats_test_types.h").write_text(shim)
    binary = output / "test_stats_schema"
    command = shlex.split(os.environ.get("CC", "cc")) + [
        "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
        *shlex.split(os.environ.get("UNIT_CFLAGS", "")),
        *(["--coverage"] if os.environ.get("COVERAGE") == "1" else []),
        "-I" + str(output), "-I" + str(ROOT / "src"),
        str(ROOT / "ci/tests/unit/test_stats_schema.c"), "-o", str(binary)]
    print("compile:", shlex.join(command), flush=True)
    subprocess.run(command, check=True)
    info = binary.stat()
    print(f"binary={binary} mtime_ns={info.st_mtime_ns} size={info.st_size}", flush=True)
    labels = ("", "main", "a-b.c_1", 'a"b', "a\\b", "a\nb", '"\\\n' * 1024)
    for mode in ("sequence", "max", "min", "state0", "state1", "state2", "state3"):
        for label in labels:
            result = subprocess.run([str(binary), mode, label], check=False,
                                    capture_output=True, text=True)
            assert result.returncode == 0, result.stderr
            body, prometheus = result.stdout.split("\n", 1)
            values = json.loads(body)
            assert list(values) == contract["json_keys"], "JSON descriptor names/order/count changed"
            expected: str | int
            for i, key in enumerate(contract["json_keys"]):
                if key == "breaker_state":
                    state = int(mode[-1]) if mode.startswith("state") else 2
                    expected = ("closed", "open", "half-open", "unknown")[state]
                elif key == "lock_ttl":
                    expected = -(2**63) if mode == "min" else 2**63 - 1
                else:
                    expected = 2**64 - 1 if mode == "max" else i + 1
                assert type(values[key]) is type(expected) and values[key] == expected, \
                    f"JSON value/type changed: {key}"
            assert body == json.dumps(values, separators=(",", ":")), "JSON bytes changed"
            escaped = label.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
            lines: list[str] = []
            for family in contract["prometheus_families"]:
                name = family["name"]
                key = name.removeprefix("cache_turbo_").removesuffix("_total")
                if key == "regen_cost_ms":
                    key = "cost_ms"
                value = values[key] if key != "breaker_state" else state
                lines.extend((f"# HELP {name} {family['help']}\n",
                              f"# TYPE {name} {family['type']}\n",
                              f'{name}{{zone="{escaped}"}} {value}\n'))
            assert prometheus == "".join(lines), "Prometheus descriptor bytes/value/escaping changed"
    print("stats-schema: 49 cases passed; exact contract, max/min, escaping, short/overflow bounds")


if __name__ == "__main__":
    # An explicit output path retains candidate binaries for mutation evidence.
    destination = os.environ.get("STATS_TEST_OUT")
    if destination:
        target = Path(destination)
        target.mkdir(parents=True, exist_ok=True)
        run(target)
    else:
        with tempfile.TemporaryDirectory(prefix="cache-turbo-stats-schema-") as directory:
            run(Path(directory))
