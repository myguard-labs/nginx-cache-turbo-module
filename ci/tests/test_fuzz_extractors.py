"""Fuzz slicers (ci/fuzz/extract_*.sh) must fail closed on a drifted source.

Each case runs a slicer against a scratch copy of the scripts and the sources
they read. The unmodified copy must extract (positive control); a source whose
function closes with a trailing comment (so a bare `}` is no longer the next
line), a continued #define, a duplicated definition or a moved typedef must be
rejected or still build the right include. Nothing here compiles.
"""
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FUZZ = REPO / "ci" / "fuzz"
SRC = REPO / "src"
# slicer -> generated include, for every ci/fuzz/extract_*.sh slicer.
SLICERS = {
    "extract_auto_classify.sh": "generated_auto_classify.inc",
    "extract_blob.sh": "generated_blob.inc",
    "extract_cache_control.sh": "generated_cache_control.inc",
    "extract_control_inputs.sh": "generated_control_inputs.inc",
    "extract_cookie_args.sh": "generated_cookie_args.inc",
    "extract_mc_parser.sh": "generated_mc_parser.inc",
    "extract_norm_args.sh": "generated_norm_args.inc",
    "extract_parser.sh": "generated_parser.inc",
    "extract_redis_readers.sh": "generated_redis_readers.inc",
    "extract_vary.sh": "generated_vary.inc",
}
# Set to a git ref to populate the scratch scripts from that ref instead of the
# working tree (used to prove the atomicity control fails on the old slicers).
REF_ENV = "FUZZ_EXTRACTOR_REF"
WAIT_S = 20  # bound on every wait so a broken shim cannot hang the suite


def end_comment(text, func):
    """Make the closing brace of `func` carry a trailing comment."""
    found = re.search(r"^" + re.escape(func) + r"\(", text, re.MULTILINE)
    assert found is not None, func
    start = found.start()
    end = text.index("\n}\n", start)
    return text[:end] + "\n} /* end */\n" + text[end + 3:]


class ExtractorTest(unittest.TestCase):
    def tree(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        root = Path(d.name)
        (root / "ci" / "fuzz").mkdir(parents=True)
        shutil.copytree(SRC, root / "src")
        for f in FUZZ.glob("*.h"):
            shutil.copy(f, root / "ci" / "fuzz")
        ref = os.environ.get(REF_ENV)
        for f in FUZZ.glob("extract_*.sh"):
            dst = root / "ci" / "fuzz" / f.name
            if ref:
                dst.write_bytes(subprocess.run(
                    ["git", "-C", str(REPO), "show", f"{ref}:ci/fuzz/{f.name}"],
                    capture_output=True, check=True).stdout)
            else:
                shutil.copy(f, dst)
        helper = root / "ci" / "fuzz" / "atomic_out.sh"
        if not ref:
            shutil.copy(FUZZ / "atomic_out.sh", helper)
        else:
            # A ref that predates the helper has none; one that carries it needs it.
            shown = subprocess.run(
                ["git", "-C", str(REPO), "show", f"{ref}:ci/fuzz/atomic_out.sh"],
                capture_output=True,
                check=False,
            )
            if shown.returncode == 0:
                helper.write_bytes(shown.stdout)
        self.root = root
        return root

    def mutate(self, name, fn):
        p = self.root / "src" / name
        p.write_text(fn(p.read_text()))

    def run_ex(self, script, **env):
        import os
        e = dict(os.environ, **env)
        return subprocess.run(
            ["bash", str(self.root / "ci" / "fuzz" / script)],
            capture_output=True, text=True, env=e, check=False)

    def inc(self, name):
        return (self.root / "ci" / "fuzz" / name)

    def leftovers(self):
        return sorted(p.name for p in (self.root / "ci" / "fuzz").iterdir()
                      if ".tmp." in p.name or ".part" in p.name)

    def test_unmodified_sources_extract(self):
        self.tree()
        for script, out in (("extract_cache_control.sh", "generated_cache_control.inc"),
                            ("extract_vary.sh", "generated_vary.inc"),
                            ("extract_control_inputs.sh", "generated_control_inputs.inc"),
                            ("extract_cookie_args.sh", "generated_cookie_args.inc"),
                            ("extract_redis_readers.sh", "generated_redis_readers.inc")):
            r = self.run_ex(script)
            self.assertEqual(r.returncode, 0, script + r.stderr)
            self.assertTrue(self.inc(out).stat().st_size > 0, script)

    def test_trailing_comment_on_closing_brace_is_rejected(self):
        cases = (
            ("extract_cache_control.sh", "ngx_http_cache_turbo_module.c",
             "ngx_http_cache_turbo_cc_has", "generated_cache_control.inc"),
            ("extract_vary.sh", "ngx_http_cache_turbo_vary.c",
             "ngx_http_cache_turbo_classify_vary_next_token", "generated_vary.inc"),
            ("extract_control_inputs.sh", "ngx_http_cache_turbo_match.c",
             "ngx_http_cache_turbo_hexval", "generated_control_inputs.inc"),
            ("extract_cookie_args.sh", "ngx_http_cache_turbo_match.c",
             "ngx_http_cache_turbo_cookie_index_add", "generated_cookie_args.inc"),
            ("extract_redis_readers.sh", "ngx_http_cache_turbo_redis.c",
             "ngx_http_cache_turbo_redis_read_preamble", "generated_redis_readers.inc"),
        )
        for script, src, func, out in cases:
            with self.subTest(script=script):
                self.tree()
                self.mutate(src, lambda t, f=func: end_comment(t, f))
                r = self.run_ex(script)
                self.assertNotEqual(r.returncode, 0, r.stdout)
                self.assertIn("next top-level declaration", r.stderr)
                self.assertFalse(self.inc(out).exists(), "no .inc left behind")

    def test_continued_define_is_rejected(self):
        self.tree()
        self.mutate("ngx_http_cache_turbo_module.h", lambda t: re.sub(
            r"^(#define NGX_HTTP_CACHE_TURBO_MAX_TAGS\s+)(\S+)",
            r"\1\\\n    \2", t, count=1, flags=re.MULTILINE))
        r = self.run_ex("extract_control_inputs.sh")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("continued with a backslash", r.stderr)

    def test_typedef_moved_above_args_max_still_extracts_both(self):
        self.tree()

        def move(t):
            end_tag = "} ngx_http_cache_turbo_argspan_t;\n\n"
            end = t.index(end_tag) + len(end_tag)
            block = t[t.rindex("typedef struct {\n", 0, end):end]
            t = t.replace(block, "")
            return t.replace("#define NGX_HTTP_CACHE_TURBO_ARGS_MAX",
                             block + "#define NGX_HTTP_CACHE_TURBO_ARGS_MAX", 1)
        self.mutate("ngx_http_cache_turbo_match.c", move)
        r = self.run_ex("extract_cookie_args.sh")
        self.assertEqual(r.returncode, 0, r.stderr)
        inc = self.inc("generated_cookie_args.inc").read_text()
        self.assertEqual(inc.count("} ngx_http_cache_turbo_argspan_t;"), 1)
        self.assertLess(inc.index("} ngx_http_cache_turbo_argspan_t;"),
                        inc.index("} ngx_http_cache_turbo_argparse_t;"))

    def test_duplicate_reader_definition_is_rejected(self):
        self.tree()

        def dup(t):
            start = t.index("static void\nngx_http_cache_turbo_redis_read_lock(")
            end = t.index("\n}\n", start) + 3
            return t[:end] + "\n" + t[start:end] + t[end:]
        self.mutate("ngx_http_cache_turbo_redis.c", dup)
        r = self.run_ex("extract_redis_readers.sh")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("exactly one definition, got 2", r.stderr)

    def test_missing_recv_decl_names_the_file(self):
        self.tree()
        self.assertEqual(self.run_ex("extract_redis_readers.sh").returncode, 0)
        self.assertTrue(self.inc("generated_redis_readers.inc").exists())
        self.mutate("ngx_http_cache_turbo_redis.c",
                    lambda t: t.replace("u_char                       recv[256];", "u_char recv_x;"))
        r = self.run_ex("extract_redis_readers.sh")
        self.assertFalse(self.inc("generated_redis_readers.inc").exists(), "stale .inc removed")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("recv[] scratch not found in", r.stderr)
        self.assertIn("ngx_http_cache_turbo_redis.c", r.stderr)
        # The shim side is reported separately and names the shim.
        self.tree()
        self.assertEqual(self.run_ex("extract_redis_readers.sh").returncode, 0)
        shim = self.root / "ci" / "fuzz" / "ngx_shim.h"
        shim.write_text(shim.read_text().replace("recv[256]", "recvx"))
        r = self.run_ex("extract_redis_readers.sh")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("shim", r.stderr)
        self.assertFalse(self.inc("generated_redis_readers.inc").exists(), "stale .inc removed")


    def test_every_slicer_extracts_deterministically_without_scratch(self):
        self.tree()
        probe = self.root / "probe"
        probe.write_text("")
        mode = stat.S_IMODE(probe.stat().st_mode)  # what a plain `> file` gets
        for script, out in SLICERS.items():
            with self.subTest(script=script):
                r = self.run_ex(script)
                self.assertEqual(r.returncode, 0, r.stderr)
                first = self.inc(out).read_bytes()
                self.assertTrue(first)
                self.assertEqual(stat.S_IMODE(self.inc(out).stat().st_mode), mode)
                self.assertEqual(self.run_ex(script).returncode, 0)
                self.assertEqual(self.inc(out).read_bytes(), first)
                self.assertEqual(self.leftovers(), [])

    def shim_awk(self):
        """PATH shim that pauses every awk call until a release file exists."""
        real = shutil.which("awk")
        self.assertIsNotNone(real)
        shimdir = self.root / "shim"
        shimdir.mkdir()
        entered, release = self.root / "entered", self.root / "release"
        shim = shimdir / "awk"
        shim.write_text(
            "#!/bin/bash\n"
            f': > "{entered}"\n'
            f"for _ in $(seq {WAIT_S * 20}); do\n"
            f'    [ -e "{release}" ] && break\n'
            "    sleep 0.05\n"
            "done\n"
            f'exec "{real}" "$@"\n')
        shim.chmod(0o755)
        return shimdir, entered, release

    def test_output_is_published_atomically(self):
        for script, out in SLICERS.items():
            with self.subTest(script=script):
                self.tree()
                self.assertEqual(self.run_ex(script).returncode, 0)
                expected = self.inc(out).read_bytes()
                sentinel = b"/* sentinel: previous complete include */\n"
                self.inc(out).write_bytes(sentinel)
                shimdir, entered, release = self.shim_awk()
                proc = subprocess.Popen(
                    ["bash", str(self.root / "ci" / "fuzz" / script)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    env=dict(os.environ, PATH=f"{shimdir}:{os.environ['PATH']}"))
                try:
                    deadline = time.monotonic() + WAIT_S
                    while not entered.exists() and time.monotonic() < deadline:
                        time.sleep(0.02)
                    self.assertTrue(entered.exists(), "slicer never reached awk")
                    # Paused mid-build: a reader must still see the old, whole file.
                    self.assertEqual(self.inc(out).read_bytes(), sentinel)
                    release.touch()
                    _, err = proc.communicate(timeout=WAIT_S)
                finally:
                    release.touch()
                    if proc.poll() is None:
                        proc.kill()
                        proc.communicate()
                self.assertEqual(proc.returncode, 0, err)
                self.assertEqual(self.inc(out).read_bytes(), expected)
                self.assertEqual(self.leftovers(), [])

    def test_forced_failure_removes_include_and_leaves_no_scratch(self):
        # (slicer, source, function whose definition we hide)
        cases = (
            ("extract_auto_classify.sh", "ngx_http_cache_turbo_match.c",
             "ngx_http_cache_turbo_auto_skip("),
            ("extract_blob.sh", "ngx_http_cache_turbo_blob.c",
             "ngx_http_cache_turbo_blob_clear_vetted("),
            ("extract_cache_control.sh", "ngx_http_cache_turbo_module.c",
             "ngx_http_cache_turbo_cc_has("),
            ("extract_control_inputs.sh", "ngx_http_cache_turbo_admin.c",
             "ngx_http_cache_turbo_warm_file_finish("),
            ("extract_cookie_args.sh", "ngx_http_cache_turbo_match.c",
             "ngx_http_cache_turbo_argparse_build("),
            ("extract_mc_parser.sh", "ngx_http_cache_turbo_memcached.c",
             "ngx_http_cache_turbo_mc_parse("),
            ("extract_norm_args.sh", "ngx_http_cache_turbo_module.c",
             "ngx_http_cache_turbo_normalized_args_variable("),
            ("extract_parser.sh", "ngx_http_cache_turbo_redis.c",
             "ngx_http_cache_turbo_redis_frame_scan_prologue("),
            ("extract_redis_readers.sh", "ngx_http_cache_turbo_redis.c",
             "ngx_http_cache_turbo_redis_read_lock("),
            ("extract_vary.sh", "ngx_http_cache_turbo_vary.c",
             "ngx_http_cache_turbo_vary_ignore_match("),
        )
        self.assertEqual({c[0] for c in cases}, set(SLICERS))
        for script, src, needle in cases:
            with self.subTest(script=script):
                self.tree()
                self.mutate(src, lambda t, n=needle: t.replace(n, n[:-1] + "_gone("))
                out = SLICERS[script]
                self.inc(out).write_text("stale\n")
                r = self.run_ex(script)
                self.assertNotEqual(r.returncode, 0, r.stdout)
                self.assertIn("failed to extract", r.stderr)
                self.assertFalse(self.inc(out).exists(), "failed run removes the .inc")
                self.assertEqual(self.leftovers(), [])

    def test_aborting_tool_removes_include_and_leaves_no_scratch(self):
        # An awk that dies (not a layout drift) must still fail closed.
        for script, out in SLICERS.items():
            with self.subTest(script=script):
                self.tree()
                shimdir = self.root / "shim"
                shimdir.mkdir()
                (shimdir / "awk").write_text("#!/bin/bash\nexit 2\n")
                (shimdir / "awk").chmod(0o755)
                self.inc(out).write_text("stale\n")
                r = self.run_ex(script, PATH=f"{shimdir}:{os.environ['PATH']}")
                self.assertNotEqual(r.returncode, 0, r.stdout)
                self.assertFalse(self.inc(out).exists(), "failed run removes the .inc")
                self.assertEqual(self.leftovers(), [])

    def test_finished_parser_include_survives_a_later_readers_failure(self):
        self.tree()
        self.mutate(
            "ngx_http_cache_turbo_redis.c",
            lambda t: t.replace(
                "ngx_http_cache_turbo_redis_read_lock(", "ngx_http_cache_turbo_redis_gone("
            ),
        )
        r = self.run_ex("extract_parser.sh")
        self.assertNotEqual(r.returncode, 0)
        self.assertTrue(self.inc("generated_parser.inc").stat().st_size > 0)
        self.assertFalse(self.inc("generated_redis_readers.inc").exists())
        self.assertEqual(self.leftovers(), [])

    def test_missing_source_boundary_keeps_the_previous_include(self):
        # extract_vary.sh checks its source before touching the output, so a
        # previously generated include survives; the control_inputs slicer
        # removes it. Both contracts are unchanged by the atomic publish.
        for script, src, kept in (("extract_vary.sh", "ngx_http_cache_turbo_vary.c", True),
                                  ("extract_control_inputs.sh",
                                   "ngx_http_cache_turbo_admin.c", False)):
            with self.subTest(script=script):
                self.tree()
                (self.root / "src" / src).unlink()
                out = SLICERS[script]
                self.inc(out).write_text("previous\n")
                r = self.run_ex(script)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("cannot find", r.stderr)
                self.assertEqual(self.inc(out).exists(), kept)
                self.assertEqual(self.leftovers(), [])

    def test_redis_readers_out_override_is_honoured(self):
        self.tree()
        alt = self.root / "alt" / "readers.inc"
        alt.parent.mkdir()
        r = self.run_ex("extract_redis_readers.sh", FUZZ_REDIS_READERS_OUT=str(alt))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.run_ex("extract_redis_readers.sh")
        self.assertEqual(alt.read_bytes(), self.inc("generated_redis_readers.inc").read_bytes())
        self.assertEqual(sorted(p.name for p in alt.parent.iterdir()), ["readers.inc"])


if __name__ == "__main__":
    unittest.main()
