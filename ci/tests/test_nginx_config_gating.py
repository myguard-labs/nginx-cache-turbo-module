#!/usr/bin/env python3
"""Fault-only directive gating in the generated nginx.conf
(CT-NGXCONF-L2-FAULT-DIRECTIVE).

Every `cache_turbo_test_*` directive exists only in a
NGX_HTTP_CACHE_TURBO_TEST_FAULTS build; a binary without it rejects the config
with "unknown directive". nginx_config() must therefore emit them only when the
run has fault injection. The optional last arm renders a full L2 config and
runs `nginx -t` against a build WITHOUT the define:

    CT_NGINX_NOFAULT=<nginx binary>[:<module .so>] python3 ci/tests/test_nginx_config_gating.py
"""

import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "ci" / "tools"))

import nginx_config as nc

DIRECTIVE = re.compile(r"^[ \t]*cache_turbo_test_\w+", re.MULTILINE)
PORTS = {"redis_port": 29903, "redis_auth_port": 29904, "redis_password": "pw",
         "memcached_port": 29905}


def render(root: pathlib.Path, fault: bool, module: pathlib.Path | None = None
           ) -> str:
    return nc.nginx_config(root, 29901, module, 29902, 1,
                           fault_injection=fault, **PORTS)


class FaultDirectiveGating(unittest.TestCase):
    root = pathlib.Path("/nonexistent-root")

    def test_non_fault_run_has_no_test_directive(self) -> None:
        conf = render(self.root, False)
        self.assertEqual(DIRECTIVE.findall(conf), [])
        # the location survives; only its fault-only knob is gone
        self.assertIn("location /l2promo/", conf)
        self.assertNotIn("promote_hold_ms", re.sub(r"#.*", "", conf))

    def test_fault_run_keeps_every_test_directive(self) -> None:
        conf = render(self.root, True)
        self.assertIn("cache_turbo_test_l2_promote_hold_ms 2000;", conf)
        self.assertIn("cache_turbo_test_scan_max_pages 2;", conf)
        self.assertIn("cache_turbo_test_restore_alloc_fail on;", conf)

    def test_strip_only_removes_directive_lines(self) -> None:
        fault = render(self.root, True)
        stripped = nc.strip_fault_directives(fault)
        self.assertEqual(
            len(fault.splitlines()) - len(stripped.splitlines()),
            len(DIRECTIVE.findall(fault)))
        self.assertIn("location /allocfail/", stripped)

    def test_strip_boundaries(self) -> None:
        src = ("a;\n"
               "    cache_turbo_test_x   on;\n"
               "\tcache_turbo_test_y 5;   \n"
               "    # cache_turbo_test_z mentioned in a comment;\n"
               "    cache_turbo_redis 127.0.0.1:1 prefix=ct:;\n"
               "    cache_turbo_testing on;\n")
        self.assertEqual(nc.strip_fault_directives(src),
                         "a;\n"
                         "    # cache_turbo_test_z mentioned in a comment;\n"
                         "    cache_turbo_redis 127.0.0.1:1 prefix=ct:;\n"
                         "    cache_turbo_testing on;\n")
        self.assertEqual(nc.strip_fault_directives(""), "")

    @unittest.skipUnless(os.environ.get("CT_NGINX_NOFAULT"),
                         "CT_NGINX_NOFAULT unset (needs a build without "
                         "NGX_HTTP_CACHE_TURBO_TEST_FAULTS)")
    def test_l2_config_passes_nginx_t_without_fault_build(self) -> None:
        binary, _, module = os.environ["CT_NGINX_NOFAULT"].partition(":")
        with tempfile.TemporaryDirectory(prefix="ct-ngxconf-") as tmp:
            root = pathlib.Path(tmp)
            (root / "logs").mkdir()
            conf = render(root, False, pathlib.Path(module) if module else None)
            (root / "nginx.conf").write_text(conf, encoding="ascii")
            res = subprocess.run(
                [binary, "-t", "-c", str(root / "nginx.conf"), "-p", str(root)],
                capture_output=True, text=True, check=False,
                env={**os.environ, "ASAN_OPTIONS": "detect_leaks=0"})
            self.assertEqual(res.returncode, 0, res.stderr[-600:])


if __name__ == "__main__":
    unittest.main()
