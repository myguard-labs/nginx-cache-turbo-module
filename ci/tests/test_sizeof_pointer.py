#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Compiler-backed sizeof-pointer controls; all C inputs are disposable."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "ci/tools/sizeof_pointer.py"
PRELUDE = """#include <string.h>
#define ngx_memcpy memcpy
typedef unsigned long ngx_atomic_uint_t;
typedef int scalar_t;
typedef char *pointer_t;
typedef int array_t[8];
"""


class SizeofPointerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sizeof-pointer-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "src").mkdir()
        self.env = os.environ.copy()
        self.env.pop("OPENROUTER_API_KEY", None)
        self.env["NGX_SRC_TREE"] = "-"
        self.env.pop("SIZEOF_POINTER_CLANG", None)
        for key in ("GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE", "GIT_COMMON_DIR"):
            self.env.pop(key, None)

    def run_check(self, text, expected=0, files=None, checker=CHECKER):
        source = self.root / "src/input.c"
        source.write_text(PRELUDE + text)
        result = subprocess.run(
            [sys.executable, str(checker), *(files or ["src/input.c"])],
            cwd=self.root, env=self.env, capture_output=True, text=True, check=False,
        )
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, expected, output)
        if expected == 1:
            self.assertIn("error[c-memcpy-sizeof-pointer]", output)
            self.assertNotIn("uncertainty", output)
        if expected == 2:
            self.assertIn("uncertainty", output)
        return output

    def test_safe_complete_objects(self):
        self.run_check("""void f(void *d, void *s) {
            ngx_atomic_uint_t value = 0; scalar_t scalar = 0;
            char array[16]; array_t alias_array;
            struct { int a; } whole;
            memcpy(d,s,sizeof(value)); memmove(d,s,sizeof scalar);
            ngx_memcpy(d,s,sizeof(array)); memcpy(d,s,sizeof alias_array);
            memcpy(d,s,sizeof(whole));
        }""")

    def test_pointer_parameters(self):
        for fn in ("memcpy", "memmove", "ngx_memcpy"):
            for size in ("sizeof(p)", "sizeof p"):
                with self.subTest(fn=fn, size=size):
                    self.run_check(f"void f(void *d, void *s, char *p) {{ {fn}(d,s,{size}); }}", 1)

    def test_public_named_suppression(self):
        output = self.run_check("""void f(void *d, void *s, char *p) {
            // ast-grep-ignore: c-memcpy-sizeof-pointer
            memcpy(d,s,sizeof(p));
        }""")
        self.assertIn("no sizeof-identifier copy lengths", output)

    def test_unrelated_named_suppression_does_not_hide_pointer(self):
        self.run_check("""void f(void *d, void *s, char *p) {
            // ast-grep-ignore: unrelated-rule
            memcpy(d,s,sizeof(p));
        }""", 1)

    def test_public_suppression_is_local_to_one_copy(self):
        self.run_check("""void f(void *d, void *s, char *p) {
            // ast-grep-ignore: c-memcpy-sizeof-pointer
            memcpy(d,s,sizeof(p));
            memmove(d,s,sizeof(p));
        }""", 1)

    def test_pointer_typedef_and_chain(self):
        self.run_check("""typedef pointer_t chained_t;
            void f(void *d, void *s) { chained_t p = 0; memcpy(d,s,sizeof(p)); }""", 1)

    def test_shadowed_scalar(self):
        self.run_check("""char *value;
            void f(void *d, void *s) { int value = 0; memcpy(d,s,sizeof(value)); }""")

    def test_shadowed_pointer(self):
        self.run_check("""int value;
            void f(void *d, void *s) { char *value = 0; memcpy(d,s,sizeof(value)); }""", 1)

    def test_mixed_declarations(self):
        self.run_check("""void f(void *d, void *s) {
            int value = 0, *p = 0, array[4];
            memcpy(d,s,sizeof(value)); memcpy(d,s,sizeof(array));
        }""")
        self.run_check("""void f(void *d, void *s) {
            int value = 0, *p = 0, array[4]; memcpy(d,s,sizeof(p));
        }""", 1)

    def test_array_parameter_decays_to_pointer(self):
        self.run_check("void f(void *d, void *s, char p[8]) { memcpy(d,s,sizeof(p)); }", 1)

    def test_pointer_to_array_and_function_pointer(self):
        for declaration in ("int (*p)[8] = 0", "void (*p)(void) = 0"):
            with self.subTest(declaration=declaration):
                self.run_check(f"void f(void *d, void *s) {{ {declaration}; memcpy(d,s,sizeof(p)); }}", 1)

    def test_safe_pointee_length_comments_strings(self):
        self.run_check('''void f(void *d, void *s, int *p) {
            memcpy(d,s,sizeof(*p)); memmove(d,s,16);
            /* memcpy(d,s,sizeof(p)); */
            const char *text = "memcpy(d,s,sizeof(p))";
        }''')

    def test_unknown_typedef_and_syntax_error_are_uncertainty(self):
        for declaration in ("unknown_type p", "int *p = ;"):
            with self.subTest(declaration=declaration):
                self.run_check(f"void f(void *d, void *s) {{ {declaration}; memcpy(d,s,sizeof(p)); }}", 2)

    def test_header_uses_actual_includer(self):
        (self.root / "src/private.h").write_text(
            "static void copy(void *d, void *s) { scalar_t value=0; memcpy(d,s,sizeof(value)); }"
        )
        self.run_check('#include "private.h"', files=["src/private.h"])
        (self.root / "src/private.h").write_text(
            "static void copy(void *d, void *s) { pointer_t value=0; memcpy(d,s,sizeof value); }"
        )
        self.run_check('#include "private.h"', 1, files=["src/private.h"])

    def test_header_without_includer_is_uncertainty(self):
        (self.root / "src/private.h").write_text(
            "static void copy(void *d, void *s) { int value=0; memcpy(d,s,sizeof(value)); }"
        )
        self.run_check("int unrelated;", 2, files=["src/private.h"])

    def test_inactive_candidate_is_uncertainty(self):
        self.run_check("""#if 0
            void f(void *d, void *s) { int *p; memcpy(d,s,sizeof(p)); }
            #endif
        """, 2)

    def test_test_faults_configuration_still_blocks(self):
        self.run_check("""#ifdef NGX_HTTP_CACHE_TURBO_TEST_FAULTS
            void f(void *d, void *s) { int *p; memcpy(d,s,sizeof(p)); }
            #endif
        """, 1)

    def test_missing_compiler_is_uncertainty(self):
        self.env["SIZEOF_POINTER_CLANG"] = "no-such-sizeof-pointer-clang"
        self.run_check("void f(void *d,void *s) { int value=0; memcpy(d,s,sizeof(value)); }", 2)

    def test_missing_configured_tree_is_uncertainty(self):
        self.env["NGX_SRC_TREE"] = str(self.root / "missing")
        self.run_check("void f(void *d,void *s) { int value=0; memcpy(d,s,sizeof(value)); }", 2)

    def test_missing_libclang_is_uncertainty(self):
        fake = self.root / "clang-no-library"
        fake.write_text("#!/bin/sh\ncase $1 in -dumpversion) echo 999999;; *) echo libclang.so.1;; esac\n")
        fake.chmod(0o755)
        self.env["SIZEOF_POINTER_CLANG"] = str(fake)
        self.run_check("void f(void *d,void *s) { int value=0; memcpy(d,s,sizeof(value)); }", 2)

    def test_malformed_candidate_stream_is_uncertainty(self):
        fake = self.root / "ast-grep"
        fake.write_text("#!/bin/sh\necho 'not json'\n")
        fake.chmod(0o755)
        self.env["PATH"] = str(self.root) + os.pathsep + self.env["PATH"]
        self.run_check("int x;", 2)

    def test_wrapper_keeps_semantic_rule_mandatory(self):
        subprocess.run(["git", "init", "-q", str(self.root)], env=self.env, check=True)
        shutil.copytree(ROOT / "ci/linter", self.root / "ci/linter")
        shutil.copytree(ROOT / "ci/ast-grep", self.root / "ci/ast-grep")
        (self.root / "ci/tools").mkdir()
        shutil.copyfile(CHECKER, self.root / "ci/tools/sizeof_pointer.py")
        for declaration, expected in (("int p = 0", 0), ("char *p = 0", 1)):
            with self.subTest(declaration=declaration):
                (self.root / "src/input.c").write_text(PRELUDE +
                    f"void f(void *d,void *s) {{ {declaration}; memcpy(d,s,sizeof p); }}")
                result = subprocess.run(
                    ["bash", "ci/linter/lint-astgrep.sh", "src/input.c"],
                    cwd=self.root, env=self.env, capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                if expected:
                    self.assertIn("error[c-memcpy-sizeof-pointer]", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
