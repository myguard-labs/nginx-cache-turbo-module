"""Fuzz slicers (ci/fuzz/extract_*.sh) must fail closed on a drifted source.

Each case runs a slicer against a scratch copy of the scripts and the sources
they read. The unmodified copy must extract (positive control); a source whose
function closes with a trailing comment (so a bare `}` is no longer the next
line), a continued #define, a duplicated definition or a moved typedef must be
rejected or still build the right include. Nothing here compiles.
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FUZZ = REPO / "ci" / "fuzz"
SRC = REPO / "src"
SOURCES = ["ngx_http_cache_turbo_module.c", "ngx_http_cache_turbo_module.h",
           "ngx_http_cache_turbo_vary.c", "ngx_http_cache_turbo_match.c",
           "ngx_http_cache_turbo_purge.c", "ngx_http_cache_turbo_filters.c",
           "ngx_http_cache_turbo_admin.c", "ngx_http_cache_turbo_redis.c"]


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
        (root / "src").mkdir()
        for f in FUZZ.glob("extract_*.sh"):
            shutil.copy(f, root / "ci" / "fuzz" / f.name)
        shutil.copy(FUZZ / "ngx_shim.h", root / "ci" / "fuzz")
        for f in SOURCES:
            shutil.copy(SRC / f, root / "src" / f)
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
            capture_output=True, text=True, env=e)

    def inc(self, name):
        return (self.root / "ci" / "fuzz" / name)

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
            r"\1\\\n    \2", t, count=1, flags=re.M))
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
        self.mutate("ngx_http_cache_turbo_redis.c",
                    lambda t: t.replace("u_char                       recv[256];", "u_char recv_x;"))
        r = self.run_ex("extract_redis_readers.sh")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("recv[] scratch not found in", r.stderr)
        self.assertIn("ngx_http_cache_turbo_redis.c", r.stderr)
        # The shim side is reported separately and names the shim.
        self.tree()
        shim = self.root / "ci" / "fuzz" / "ngx_shim.h"
        shim.write_text(shim.read_text().replace("recv[256]", "recvx"))
        r = self.run_ex("extract_redis_readers.sh")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("shim", r.stderr)


if __name__ == "__main__":
    unittest.main()
