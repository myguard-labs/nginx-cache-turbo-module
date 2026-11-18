"""Registry ci/fuzz/targets.tsv: positive, negative control and malformed rows."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

FUZZ = Path(__file__).resolve().parents[1] / "fuzz"
HELPER = FUZZ / "targets.sh"
FIVE = ["fuzz_resp_parser", "fuzz_norm_args", "fuzz_mc_parser",
        "fuzz_auto_classify", "fuzz_blob"]
HEADER = "name\tsource\tcorpus\tdict\textract\n"
GOOD = "fuzz_norm_args\tfuzz_norm_args.c\tcorpus_norm_args\t-\textract_norm_args.sh"


def run(cmd, registry=None):
    env = dict(os.environ)
    if registry is not None:
        env["FUZZ_TARGETS_TSV"] = str(registry)
    return subprocess.run(["bash", str(HELPER), *cmd], env=env,
                          capture_output=True, text=True)


class TargetsRegistryTest(unittest.TestCase):
    def scratch(self, body):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        p = Path(d.name) / "targets.tsv"
        p.write_text(body)
        return p

    def test_real_registry_is_the_five_targets(self):
        r = run(["validate"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(run(["names"]).stdout.split(), FIVE)
        self.assertEqual(run(["specs", "all"]).stdout.split(), [
            "fuzz_resp_parser:corpus:fuzz.dict",
            "fuzz_norm_args:corpus_norm_args:",
            "fuzz_mc_parser:corpus_mc:fuzz_mc.dict",
            "fuzz_auto_classify:corpus_auto:",
            "fuzz_blob:corpus_blob:"])

    def test_lane_partition_covers_every_target_once(self):
        a = run(["specs", "a"]).stdout.split()
        b = run(["specs", "b"]).stdout.split()
        self.assertEqual(a + b, run(["specs", "all"]).stdout.split())
        self.assertEqual((len(a), len(b)), (3, 2))
        self.assertEqual(run(["specs", "c"]).returncode, 2)

    def test_scratch_registry_good_row(self):
        r = run(["names"], self.scratch(HEADER + GOOD + "\n"))
        self.assertEqual((r.returncode, r.stdout.split()), (0, ["fuzz_norm_args"]))

    def test_missing_source_fails_naming_the_row(self):
        row = GOOD.replace("fuzz_norm_args\t", "fuzz_nope\t").replace(
            "fuzz_norm_args.c", "fuzz_nope.c")
        r = run(["validate"], self.scratch(HEADER + GOOD + "\n" + row + "\n"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("row 'fuzz_nope'", r.stderr)
        self.assertIn("harness source 'fuzz_nope.c' not found", r.stderr)

    def test_missing_corpus_dict_extract_fail(self):
        for col, field in ((2, "corpus_nope"), (3, "nope.dict"), (4, "extract_nope.sh")):
            cols = GOOD.split("\t")
            cols[col] = field
            r = run(["validate"], self.scratch(HEADER + "\t".join(cols) + "\n"))
            self.assertEqual(r.returncode, 1, field)
            self.assertIn("row 'fuzz_norm_args'", r.stderr)
            self.assertIn(field, r.stderr)

    def test_malformed_rows_fail(self):
        cases = {
            "too few columns": "fuzz_norm_args\tfuzz_norm_args.c\tcorpus_norm_args\t-",
            "too many columns": GOOD + "\textra",
            "empty name": "\tfuzz_norm_args.c\tcorpus_norm_args\t-\textract_norm_args.sh",
            "bad name": "norm\tfuzz_norm_args.c\tcorpus_norm_args\t-\textract_norm_args.sh",
            "empty dict": "fuzz_norm_args\tfuzz_norm_args.c\tcorpus_norm_args\t\textract_norm_args.sh",
            "duplicate": GOOD + "\n" + GOOD,
        }
        for label, row in cases.items():
            r = run(["validate"], self.scratch(HEADER + row + "\n"))
            self.assertEqual(r.returncode, 1, label)
            self.assertIn("targets:", r.stderr, label)

    def test_empty_and_missing_registry_fail(self):
        self.assertEqual(run(["validate"], self.scratch(HEADER)).returncode, 1)
        self.assertEqual(run(["validate"], Path("/nonexistent/targets.tsv")).returncode, 1)

    def test_build_fails_on_bad_row_before_compiling(self):
        row = GOOD.replace("fuzz_norm_args.c", "fuzz_nope.c")
        env = dict(os.environ, FUZZ_TARGETS_TSV=str(self.scratch(HEADER + row + "\n")))
        with tempfile.TemporaryDirectory() as out:
            r = subprocess.run(["bash", str(FUZZ / "build.sh"), out], env=env,
                               capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("row 'fuzz_norm_args'", r.stderr)


if __name__ == "__main__":
    unittest.main()
