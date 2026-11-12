# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Inert compiler controls for the shipped make capture and workflow steps."""

import concurrent.futures
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
RECORDER = ROOT / "ci/tools/record_compile.py"
BUILD = (ROOT / "ci/tools/ci-build.sh").read_text()
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/static.yml").read_text())
STEPS = [step for job in WORKFLOW["jobs"].values() for step in job.get("steps", [])]


def step_run(name):
    return next(step["run"] for step in STEPS if step.get("name") == name)


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(
            self.enterContext(tempfile.TemporaryDirectory(prefix="compile-capture-"))
        )
        self.capture = self.root / "capture"
        self.capture.mkdir()
        self.calls = self.root / "calls"
        self.calls.mkdir()
        self.compiler = self.root / "compiler"
        self.compiler.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys, tempfile\n"
            "with tempfile.NamedTemporaryFile(mode='w', dir=os.environ['CALLS'], "
            "delete=False) as f: json.dump(sys.argv[1:], f)\n"
            "sys.exit(int(os.environ.get('COMPILER_STATUS', '0')))\n"
        )
        self.compiler.chmod(0o755)
        self.env = dict(
            os.environ, CT_COMPILE_COMMANDS_DIR=str(self.capture), CALLS=str(self.calls)
        )
        self.source = self.root / "source with space.c"
        self.source.touch()

    def run_capture(self, *args, **env):
        return subprocess.run(
            [sys.executable, str(RECORDER), *map(str, args)],
            cwd=self.root,
            env=dict(self.env, **env),
            capture_output=True,
            text=True,
            check=False,
        )

    def entries(self):
        return [json.loads(p.read_text()) for p in self.capture.glob("*.json")]

    def test_exact_argv_and_parallel_fragments(self):
        args = [
            str(self.compiler),
            "-c",
            "-DVALUE=space 'quote' $literal;",
            "-Iinclude with spaces",
            "-o",
            "object with spaces.o",
            str(self.source),
        ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.run_capture(*args), range(8)))
        self.assertEqual([r.returncode for r in results], [0] * 8)
        self.assertEqual(len(self.entries()), 8)
        for entry in self.entries():
            self.assertEqual(entry["arguments"], args)
            self.assertEqual(entry["file"], str(self.source))
            self.assertEqual(entry["directory"], str(self.root))
        self.assertEqual(
            [json.loads(p.read_text()) for p in self.calls.iterdir()], [args[1:]] * 8
        )

    def test_ccache_miss_and_hit_preserve_compiler_arguments(self):
        launcher = self.root / "ccache"
        launcher.write_text(
            '#!/bin/sh\nif [ "${CACHE_HIT:-}" = 1 ]; then exit 0; fi\nexec "$@"\n'
        )
        launcher.chmod(0o755)
        args = [str(self.compiler), "-c", str(self.source), "-DFAULT=1"]
        self.assertEqual(self.run_capture(launcher, *args).returncode, 0)
        self.assertEqual(self.run_capture(launcher, *args, CACHE_HIT="1").returncode, 0)
        self.assertEqual([e["arguments"] for e in self.entries()], [args, args])
        self.assertEqual(len(list(self.calls.iterdir())), 1)

    def test_noncompile_and_failed_compile_are_not_published(self):
        self.assertEqual(self.run_capture(self.compiler, "--version").returncode, 0)
        result = self.run_capture(
            self.compiler, "-c", self.source, COMPILER_STATUS="37"
        )
        self.assertEqual(result.returncode, 37)
        self.assertEqual(self.entries(), [])
        result = self.run_capture("--merge", self.capture, "db.json")
        self.assertEqual(result.returncode, 2)
        self.assertIn("no C compile commands captured", result.stderr)
        self.assertFalse((self.root / "db.json").exists())

    def test_signal_status_is_preserved(self):
        self.compiler.write_text(
            f"#!{sys.executable}\nimport os, signal\nos.kill(os.getpid(), signal.SIGTERM)\n"
        )
        self.assertEqual(
            self.run_capture(self.compiler, "-c", self.source).returncode, 143
        )
        self.assertEqual(self.entries(), [])

    def test_capture_errors_fail_closed(self):
        for args in [[], ["--merge"], [str(self.root / "missing")]]:
            self.assertEqual(self.run_capture(*args).returncode, 2)
        self.assertEqual(
            self.run_capture(
                self.compiler, CT_COMPILE_COMMANDS_DIR="absent"
            ).returncode,
            2,
        )
        (self.capture / "broken.json").write_text("{")
        self.assertEqual(
            self.run_capture("--merge", self.capture, "db.json").returncode, 2
        )
        self.assertFalse((self.root / "db.json").exists())

    def prepare_workflow(self):
        """Use shipped compiler selection, flags, make calls and YAML shell."""
        tools = self.root / "ci/tools"
        tools.mkdir(parents=True)
        shutil.copyfile(RECORDER, tools / RECORDER.name)
        source_dir = self.root / "src"
        source_dir.mkdir()
        sources = sorted((ROOT / "src").glob("*.c"))
        for source in sources:
            (source_dir / source.name).touch()
        tree = self.root / ".build/nginx-fixture"
        tree.mkdir(parents=True)
        # Fixture make targets invoke only the inert argv-writing compiler.
        targets = [f"object-{i}" for i in range(len(sources))]
        lines = [
            ".PHONY: modules " + " ".join(targets),
            "modules: " + " ".join(targets),
        ]
        for target, source in zip(targets, sources, strict=True):
            lines += [
                f"{target}:",
                f"\t$(CC) $(CC_OPT) -c -o {target}.o {source_dir / source.name}",
            ]
        (tree / "objs").mkdir()
        (tree / "objs/Makefile").write_text("\n".join(lines) + "\n")
        # Match nginx's recursive make entry point, including status propagation.
        (tree / "Makefile").write_text(
            ".PHONY: modules\nmodules:\n\t$(MAKE) -f objs/Makefile modules\n"
        )
        selection = BUILD[BUILD.index('CC="${CC:-cc}"') : BUILD.index("\nCC_OPT=")]
        faults = next(
            line for line in BUILD.splitlines() if line.startswith("TEST_OPT=")
        )
        flags = next(line for line in BUILD.splitlines() if line.startswith("CC_OPT="))
        tail = BUILD[BUILD.index("# Compilation database capture:") :]
        (tools / "ci-build.sh").write_text(
            "#!/bin/bash\nset -euo pipefail\n"
            'test "$1/$2/$3" = nginx/fixture/module\n'
            'MODULE_DIR="$GITHUB_WORKSPACE"\nROOT="$MODULE_DIR/.build"\n'
            "DIR=nginx-fixture\nMODE=module\n"
            + selection
            + "\n"
            + faults
            + "\n"
            + flags
            + '\nexport CC_OPT\nMAKE=make\ncd "$ROOT/$DIR"\n'
            + tail
        )
        return dict(
            self.env,
            GITHUB_WORKSPACE=str(self.root),
            WS=str(self.root),
            NGINX_VERSION="fixture",
            CC=str(self.compiler),
            CT_NO_CCACHE="1",
        )

    def run_workflow(self, env):
        return subprocess.run(
            ["bash", "-c", step_run("Build module and capture the real compile flags")],
            cwd=self.root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_workflow_actual_flags_coverage_and_missing_source_control(self):
        env = self.prepare_workflow()
        result = self.run_workflow(env)
        self.assertEqual(result.returncode, 0, result.stderr)
        db_path = self.root / "compile_commands.json"
        db = json.loads(db_path.read_text())
        calls = [json.loads(p.read_text()) for p in self.calls.iterdir()]
        self.assertCountEqual([e["arguments"][1:] for e in db], calls)
        self.assertEqual(len(db), len(list((ROOT / "src").glob("*.c"))))
        for entry in db:
            self.assertIn("-DNGX_HTTP_CACHE_TURBO_TEST_FAULTS=1", entry["arguments"])
            self.assertIn("-DNGX_DEBUG_PALLOC=1", entry["arguments"])
            self.assertIn("-O0", entry["arguments"])
        validator = step_run("Verify compilation database covers src/")

        def validate():
            return subprocess.run(
                ["bash", "-c", validator],
                cwd=self.root,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(validate().returncode, 0)
        db_path.write_text(json.dumps(db[1:]))
        red = validate()
        self.assertNotEqual(red.returncode, 0)
        self.assertIn("compile_commands.json missing:", red.stderr)
        print("negative control missing-source: " + red.stderr.strip())
        db_path.write_text(json.dumps(db))
        self.assertEqual(validate().returncode, 0)

    def test_workflow_compiler_failure_stops_merge(self):
        env = self.prepare_workflow()
        env["COMPILER_STATUS"] = "37"
        result = self.run_workflow(env)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "compile_commands.json").exists())

    def test_make_without_capture_preserves_selected_compiler(self):
        block = BUILD.split("# Compilation database capture:", 1)[1].split(
            "# End compilation database capture.", 1
        )[0]
        result = subprocess.run(
            [
                "bash",
                "-c",
                'set -eu; WITH_CC="ccache cc"; '
                + "# "
                + block
                + '\nprintf "%s" "${#CAPTURE_MAKE_ARGS[@]}"',
            ],
            env=dict(os.environ, CT_COMPILE_COMMANDS_DIR=""),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "0")


if __name__ == "__main__":
    unittest.main()
