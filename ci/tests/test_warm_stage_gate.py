"""Exercise the warm-stage controller's release and fail-closed paths."""
import json
import pathlib
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
from areas import admin


class WarmStageGate(unittest.TestCase):
    def run_controller(self, mode):
        paths = []
        controls = []
        with tempfile.TemporaryDirectory() as tmp:
            ng = types.SimpleNamespace(root=pathlib.Path(tmp), port=0)

            def fetch(_port, path, **kwargs):
                if kwargs.get("method") == "POST":
                    source = pathlib.Path(path.split("url_file=", 1)[1])
                    entered = source.with_name(source.name + ".entered")
                    wait = source.with_name(source.name + ".wait")
                    paths.append((entered, wait))
                    self.assertTrue(wait.is_file())
                    if mode == "missing":
                        return 200, '{"warmed":0}', {}
                    if mode != "deadline":
                        entered.touch()
                    deadline = time.monotonic() + 2
                    while wait.exists() and time.monotonic() < deadline:
                        time.sleep(0.001)
                    self.assertFalse(wait.exists(), "controller failed to release")
                    if mode != "escape":
                        entered.write_bytes(b"1")
                    return 200, json.dumps({"warmed": 0}), {}
                controls.append(path)
                if mode == "network":
                    raise OSError("control request failed")
                if mode == "timeout":
                    raise TimeoutError("control request timed out")
                return (500 if mode == "status" else 200), "", {}

            with mock.patch.object(admin, "fetch", side_effect=fetch), \
                    mock.patch.object(admin, "sanitizer_time_scale",
                                      return_value=0.01 if mode == "deadline" else 1):
                if mode == "positive":
                    admin.test_warm_url_file_io_stages_run_off_event_loop(ng)
                elif mode == "network":
                    with self.assertRaisesRegex(OSError, "control request failed"):
                        admin.test_warm_url_file_io_stages_run_off_event_loop(ng)
                else:
                    message = {"missing": "stage entry was not signalled",
                               "deadline": "stage entry was not signalled",
                               "timeout": "worker unresponsive during delayed open",
                               "status": "worker unresponsive during delayed open",
                               "escape": "gate escaped before release"}[mode]
                    with self.assertRaisesRegex(AssertionError, message):
                        admin.test_warm_url_file_io_stages_run_off_event_loop(ng)
            self.assertTrue(paths)
            for entered, wait in paths:
                self.assertFalse(wait.exists())
                self.assertFalse(entered.exists())
            return len(paths), len(controls)

    def test_positive_all_stages(self):
        self.assertEqual(self.run_controller("positive"), (3, 3))

    def test_missing_entry_fails(self):
        self.assertEqual(self.run_controller("missing"), (1, 0))

    def test_missing_entry_deadline_releases(self):
        self.assertEqual(self.run_controller("deadline"), (1, 0))

    def test_control_timeout_names_stage_and_releases(self):
        self.assertEqual(self.run_controller("timeout"), (1, 1))

    def test_control_network_failure_releases(self):
        self.assertEqual(self.run_controller("network"), (1, 1))

    def test_control_status_failure_releases(self):
        self.assertEqual(self.run_controller("status"), (1, 1))

    def test_escape_cannot_pass_as_success(self):
        self.assertEqual(self.run_controller("escape"), (1, 1))


if __name__ == "__main__":
    unittest.main()
