"""Isolated stats configs support static/dynamic nginx without starting servers."""
import os
import pathlib
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from areas import admin


class StopBeforeServer(Exception):
    """The config is ready; no runtime command is authorized in these units."""



class StatsConfigTests(unittest.TestCase):
    def check_mode(self, module):
        ng = types.SimpleNamespace(module=module, binary=pathlib.Path("/fixture/nginx"),
                                   runner=["/fixture/runner"], port=20990, origin_port=20991)
        for name in ("test_admin_raw_zone_labels", "test_admin_stats_reload_restart"):
            with self.subTest(fixture=name, module=module):

                def inspect(command):
                    config = pathlib.Path(command[command.index("-c") + 1]).read_text()
                    self.assertNotIn("load_module None", config)
                    if module is None:
                        self.assertNotIn("load_module", config)
                    else:
                        self.assertEqual(config.count(f"load_module {module};\n"), 1)
                    self.assertEqual(command[:2], ng.runner + [str(ng.binary)])
                    return config

                def config_check(command, **kwargs):
                    config = inspect(command)
                    self.assertEqual(command[-1], "-t")
                    self.assertIn("env", kwargs)
                    for variable in ("ASAN_OPTIONS", "LSAN_OPTIONS"):
                        self.assertEqual(kwargs["env"][variable], "detect_leaks=1:detect_leaks=0")
                        self.assertEqual(os.environ[variable], "detect_leaks=1")
                    invalid = 'cache_turbo_zone "name="' in config
                    return types.SimpleNamespace(returncode=int(invalid), stderr="invalid empty zone")

                def launch(command, **kwargs):
                    inspect(command)
                    # The real server inherits the original leak settings.
                    self.assertTrue("env" not in kwargs, "server environment must remain inherited")
                    for variable in ("ASAN_OPTIONS", "LSAN_OPTIONS"):
                        self.assertEqual(os.environ[variable], "detect_leaks=1")
                    raise StopBeforeServer

                with mock.patch.dict(os.environ, ASAN_OPTIONS="detect_leaks=1",
                                     LSAN_OPTIONS="detect_leaks=1", clear=True), \
                     mock.patch("subprocess.run", side_effect=config_check) as checked, \
                     mock.patch("subprocess.Popen", side_effect=launch) as started:
                    with self.assertRaises(StopBeforeServer):
                        getattr(admin, name)(ng)
                    self.assertEqual(started.call_count, 1)
                    self.assertEqual(checked.call_count, 2 if name.endswith("zone_labels") else 0)

    def test_static_configs(self):
        self.check_mode(None)

    def test_dynamic_configs(self):
        self.check_mode(pathlib.Path("/fixture/cache_turbo.so"))


if __name__ == "__main__":
    unittest.main()
