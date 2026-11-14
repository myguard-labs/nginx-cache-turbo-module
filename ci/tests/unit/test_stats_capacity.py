#!/usr/bin/env python3
"""Compile production stats sampling; falsify lock placement and scalar bounds."""
import os
import re
import shlex
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def run(output: Path) -> None:
    module = (ROOT / "src/ngx_http_cache_turbo_module.h").read_text()
    source = (ROOT / "src/ngx_http_cache_turbo_shm.c").read_text()
    end = module.index("} ngx_http_cache_turbo_stats_t;")
    start = module.rindex("typedef struct {", 0, end)
    fields = module[start + len("typedef struct {"):end]
    start = source.index("void\nngx_http_cache_turbo_shm_stats(")
    end = source.index("\n}", start) + 2
    stats = source[start:end]
    # Counter reads and scalar arithmetic only: no work proportional to entries.
    code = re.sub(r"/\*.*?\*/|//[^\n]*", "", stats, flags=re.DOTALL)
    assert not re.search(r"\b(for|while|do|ngx_rbtree\w*|ngx_queue\w*)\b", code), \
        "stats must not traverse cache entries"
    types = """#include <stdint.h>
#include <stddef.h>
typedef unsigned char u_char;
typedef uintptr_t ngx_atomic_uint_t;
typedef uintptr_t ngx_uint_t;
typedef struct { int depth; } ngx_shmtx_t;
typedef struct { ngx_shmtx_t mutex; u_char *end; ngx_uint_t pfree; } ngx_slab_pool_t;
"""
    types += "typedef struct {" + fields + "} ngx_http_cache_turbo_stats_t;\n"
    types += "typedef struct {" + fields + "\nngx_uint_t cost_sum_ms, cost_count; } shctx_t;\n"
    types += """typedef struct { shctx_t *sh; ngx_slab_pool_t *pool; } ngx_http_cache_turbo_zone_t;
#define ngx_http_cache_turbo_zone_sh(z) ((z)->sh)
#define ngx_http_cache_turbo_zone_pool(z) ((z)->pool)
#define ngx_http_cache_turbo_zone_mutex(z) (&(z)->pool->mutex)
static size_t ngx_pagesize = 4096;
void ngx_shmtx_lock(ngx_shmtx_t *mutex);
void ngx_shmtx_unlock(ngx_shmtx_t *mutex);
"""
    line = source[:start].count("\n") + 1
    types += f'#line {line} "{ROOT / "src/ngx_http_cache_turbo_shm.c"}"\n'
    (output / "capacity_test_source.h").write_text(types + stats + "\n")
    binary = output / "test_stats_capacity"
    command = shlex.split(os.environ.get("CC", "cc")) + [
        "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
        *shlex.split(os.environ.get("UNIT_CFLAGS", "")),
        *(["--coverage"] if os.environ.get("COVERAGE") == "1" else []),
        "-I" + str(output), str(ROOT / "ci/tests/unit/test_stats_capacity.c"),
        "-o", str(binary)]
    print("compile:", shlex.join(command), flush=True)
    subprocess.run(command, check=True)
    info = binary.stat()
    print(f"binary={binary} mtime_ns={info.st_mtime_ns} size={info.st_size}", flush=True)
    subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    destination = os.environ.get("CAPACITY_TEST_OUT")
    if destination:
        target = Path(destination)
        target.mkdir(parents=True, exist_ok=True)
        run(target)
    else:
        with tempfile.TemporaryDirectory(prefix="cache-turbo-stats-capacity-") as directory:
            run(Path(directory))
