#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise capacity runner retention and real gcovr discovery."""
import json
import os
import subprocess
import tempfile
from pathlib import Path

UNIT = Path(__file__).resolve().parent
ROOT = UNIT.parents[2]


def main() -> None:
    runner = (UNIT / "run.sh").read_text()
    section = runner.split("# --- capacity sampling:", 1)[1].split("\n", 1)[1].split("# --- auto-Vary", 1)[0]
    with tempfile.TemporaryDirectory(prefix="capacity-coverage-", dir=UNIT) as directory:
        base = Path(directory)
        (base / "test_stats_capacity.py").symlink_to(UNIT / "test_stats_capacity.py")
        env = os.environ.copy()
        env.pop("CAPACITY_TEST_OUT", None)
        env.update(DIR=str(base), COVERAGE="1")
        subprocess.run(["bash", "-eu", "-c", section], env=env, check=True)
        output = base / "stats-capacity-coverage"
        assert list(output.glob("*.gcno")), "missing retained gcno"
        assert list(output.glob("*.gcda")), "missing retained gcda"
        if os.environ.get("DELETE_CAPACITY_COVERAGE") == "1":
            for path in output.glob("*.gc*"):
                path.unlink()
        report = base / "coverage.json"
        subprocess.run(["gcovr", str(base), "--root", str(ROOT), "--filter", str(ROOT / "src") + "/",
                        "--object-directory", str(UNIT), "--gcov-ignore-errors=all",
                        "--merge-mode-functions=merge-use-line-min", "--json", str(report)], check=True)
        data = json.loads(report.read_text())
        source = [f for f in data["files"] if f["file"].endswith("ngx_http_cache_turbo_shm.c")]
        assert source and any(line["count"] > 0 for line in source[0]["lines"]), \
            "production capacity source missing from coverage report"
        override = base / "override with spaces"
        env["CAPACITY_TEST_OUT"] = str(override)
        subprocess.run(["bash", "-eu", "-c", section], env=env, check=True)
        assert list(override.glob("*.gcda")) and list(override.glob("*.gcno")), "override not retained"
        scratch = base / "temporary"
        scratch.mkdir()
        env.pop("CAPACITY_TEST_OUT")
        env.update(COVERAGE="0", TMPDIR=str(scratch))
        subprocess.run(["bash", "-eu", "-c", section], env=env, check=True)
        assert not list(scratch.iterdir()), "non-coverage runner output was not cleaned"
        env["COVERAGE"] = "1"
        subprocess.run(["python3", str(UNIT / "test_stats_capacity.py")], env=env, check=True)
        assert not list(scratch.iterdir()), "standalone capacity output was not cleaned"
        env.update(CC="/bin/false", COVERAGE="1", CAPACITY_TEST_OUT=str(base / "error"))
        failed = subprocess.run(["bash", "-eu", "-c", section], env=env, capture_output=True, check=False)
        assert failed.returncode != 0, "compiler failure was ignored"
        print("capacity coverage: discovery, override, cleanup and compiler error passed")


if __name__ == "__main__":
    main()
