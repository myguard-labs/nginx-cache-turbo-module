#!/usr/bin/env python3
"""Exercise schema compiler instrumentation and gcovr discovery."""
import json
import os
import subprocess
import tempfile
from pathlib import Path

UNIT = Path(__file__).resolve().parent
ROOT = UNIT.parents[2]


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="stats-coverage-", dir=UNIT) as directory:
        base = Path(directory)
        output = base / "output with spaces"
        argv = base / "argv.json"
        wrapper = base / "compiler"
        wrapper.write_text("#!/usr/bin/env python3\n"
                           "import json, os, sys\n"
                           "open(os.environ['ARGV_LOG'], 'w').write(json.dumps(sys.argv[1:]))\n"
                           "args = sys.argv[1:]\n"
                           "if os.environ.get('DROP_COVERAGE') == '1':\n"
                           "    args = [a for a in args if a != '--coverage']\n"
                           "    open(os.environ['ARGV_LOG'], 'w').write(json.dumps(args))\n"
                           "os.execvp('cc', ['cc'] + args)\n")
        wrapper.chmod(0o755)
        env = os.environ.copy()
        env.update(CC=str(wrapper), UNIT_CFLAGS="-DTEST_COVERAGE_SENTINEL=1",
                   COVERAGE="1", STATS_TEST_OUT=str(output), ARGV_LOG=str(argv))
        subprocess.run(["python3", str(UNIT / "test_stats_schema.py")], env=env, check=True)
        args = json.loads(argv.read_text())
        assert "--coverage" in args, "renderer compiler lost --coverage"
        assert "-DTEST_COVERAGE_SENTINEL=1" in args, "renderer compiler lost UNIT_CFLAGS"
        assert list(output.glob("*.gcno")), "missing retained gcno"
        assert list(output.glob("*.gcda")), "missing retained gcda"
        scan = base / "empty" if os.environ.get("EXCLUDE_OUTPUT") == "1" else UNIT
        scan.mkdir(exist_ok=True)
        report = base / "coverage.json"
        subprocess.run(["gcovr", str(scan), "--root", str(ROOT), "--filter", str(ROOT / "src") + "/",
                        "--object-directory", str(UNIT), "--gcov-ignore-errors=all",
                        "--merge-mode-functions=merge-use-line-min", "--json", str(report)], check=True)
        data = json.loads(report.read_text())
        schema = [f for f in data["files"] if f["file"].endswith("ngx_http_cache_turbo_stats_schema.h")]
        assert schema and any(line["count"] > 0 for line in schema[0]["lines"]), \
            "production schema missing from coverage report"
        if os.environ.get("EVIDENCE_REPORT"):
            Path(os.environ["EVIDENCE_REPORT"]).write_text(report.read_text())
        env.update(COVERAGE="0", STATS_TEST_OUT=str(base / "plain"))
        subprocess.run(["python3", str(UNIT / "test_stats_schema.py")], env=env, check=True)
        assert "--coverage" not in json.loads(argv.read_text()), "COVERAGE=0 unexpectedly instrumented"
        assert not list((base / "plain").glob("*.gcno")), "plain renderer produced gcno"
        scratch = base / "temporary"
        scratch.mkdir()
        env.pop("STATS_TEST_OUT")
        env["TMPDIR"] = str(scratch)
        subprocess.run(["python3", str(UNIT / "test_stats_schema.py")], env=env, check=True)
        assert not list(scratch.iterdir()), "standalone renderer did not clean temporary output"
        env.update(CC="/bin/false", STATS_TEST_OUT=str(base / "error"))
        failed = subprocess.run(["python3", str(UNIT / "test_stats_schema.py")], env=env,
                                capture_output=True, check=False)
        assert failed.returncode != 0, "compiler failure was ignored"
        print("stats coverage wiring: instrumentation, discovery, boundary and compiler error passed")


if __name__ == "__main__":
    main()
